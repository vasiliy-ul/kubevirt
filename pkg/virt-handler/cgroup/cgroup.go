/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2021
 *
 */

package cgroup

//go:generate mockgen -source $GOFILE -package=$GOPACKAGE -destination=generated_mock_$GOFILE

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/devices"
	"github.com/opencontainers/runc/libcontainer/cgroups/ebpf"
	"github.com/opencontainers/runc/libcontainer/cgroups/ebpf/devicefilter"
	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"

	"golang.org/x/sys/unix"
)

const (
	procMountPoint   = "/proc"
	cgroupMountPoint = "/sys/fs/cgroup"
)

var (
	errNoPreciseMatch = errors.New("resulting devices cgroup doesn't precisely match target")
	errNoMatch        = errors.New("resulting devices cgroup doesn't match target mode")
)

type attachDeviceFilterFunc = func(insts asm.Instructions, license string, dirFD int) (func() error, error)

func ControllerPath(controller string) string {
	return controllerPath(cgroups.IsCgroup2UnifiedMode(), cgroupMountPoint, controller)
}

func controllerPath(isCgroup2UnifiedMode bool, cgroupMount, controller string) string {
	if isCgroup2UnifiedMode {
		return cgroupMount
	}
	return filepath.Join(cgroupMount, controller)
}

func CPUSetPath() string {
	return cpuSetPath(cgroups.IsCgroup2UnifiedMode(), cgroupMountPoint)
}

func cpuSetPath(isCgroup2UnifiedMode bool, cgroupMount string) string {
	if isCgroup2UnifiedMode {
		return filepath.Join(cgroupMount, "cpuset.cpus.effective")
	}
	return filepath.Join(cgroupMount, "cpuset", "cpuset.cpus")
}

type Parser interface {
	// Parse retrieves the cgroup data for the given process id and returns a
	// map of controllers to slice paths.
	Parse(pid int) (map[string]string, error)
}

type v1Parser struct {
	procMount string
}

func (v1 *v1Parser) Parse(pid int) (map[string]string, error) {
	return cgroups.ParseCgroupFile(filepath.Join(v1.procMount, strconv.Itoa(pid), "cgroup"))
}

type v2Parser struct {
	procMount   string
	cgroupMount string
}

func (v2 *v2Parser) Parse(pid int) (map[string]string, error) {
	slices, err := cgroups.ParseCgroupFile(filepath.Join(v2.procMount, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return nil, err
	}

	slice, ok := slices[""]
	if !ok {
		return nil, fmt.Errorf("Slice not found for PID %d", pid)
	}

	availableControllers, err := v2.getAvailableControllers(slice)
	if err != nil {
		return nil, err
	}

	// For cgroup v2 there are no per-controller paths.
	slices = make(map[string]string)
	for _, c := range availableControllers {
		slices[c] = slice
	}

	return slices, nil
}

// getAvailableControllers returns all controllers available for the cgroup.
// Based on GetAllSubsystems from
//  https://github.com/opencontainers/runc/blob/ff819c7e9184c13b7c2607fe6c30ae19403a7aff/libcontainer/cgroups/utils.go#L80
func (v2 *v2Parser) getAvailableControllers(slice string) ([]string, error) {
	// "pseudo" controllers do not appear in /sys/fs/cgroup/.../cgroup.controllers.
	// - devices: implemented in kernel 4.15
	// - freezer: implemented in kernel 5.2
	// We assume these are always available, as it is hard to detect availability.
	pseudo := []string{"devices", "freezer"}
	data, err := ioutil.ReadFile(filepath.Join(v2.cgroupMount, slice, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	subsystems := append(pseudo, strings.Fields(string(data))...)
	return subsystems, nil
}

func NewParser() Parser {
	return newParser(cgroups.IsCgroup2UnifiedMode(), procMountPoint, cgroupMountPoint)
}

func newParser(isCgroup2UnifiedMode bool, procMount, cgroupMount string) Parser {
	if isCgroup2UnifiedMode {
		return &v2Parser{
			procMount:   procMount,
			cgroupMount: cgroupMount,
		}
	}
	return &v1Parser{
		procMount: procMount,
	}
}

type DeviceController interface {
	// UpdateBlockMajorMinor applies whitelist rule for the block device identified
	// by the given major, minor and path.
	UpdateBlockMajorMinor(major, minor int64, path string, allow, skipSafetyCheck bool) error
}

type v1DeviceController struct {
}

func (v1 *v1DeviceController) UpdateBlockMajorMinor(major, minor int64, path string, allow, skipSafetyCheck bool) error {
	deviceRule := newBlockDeviceRule(major, minor, allow)
	return updateDevicesList(path, deviceRule, skipSafetyCheck)
}

func newBlockDeviceRule(major, minor int64, allow bool) *configs.DeviceRule {
	return &configs.DeviceRule{
		Type:        configs.BlockDevice,
		Major:       major,
		Minor:       minor,
		Permissions: "rwm",
		Allow:       allow,
	}
}

func updateDevicesList(path string, rule *configs.DeviceRule, skipSafetyCheck bool) error {
	// Create the target emulator for comparison later.
	target, err := loadEmulator(path)
	if err != nil {
		return err
	}
	target.Apply(*rule)

	file := "devices.deny"
	if rule.Allow {
		file = "devices.allow"
	}
	if err := fscommon.WriteFile(path, file, rule.CgroupString()); err != nil {
		return err
	}

	// Final safety check -- ensure that the resulting state is what was
	// requested. This is only really correct for white-lists, but for
	// black-lists we can at least check that the cgroup is in the right mode.
	currentAfter, err := loadEmulator(path)
	if err != nil {
		return err
	}
	if !skipSafetyCheck {
		if !target.IsBlacklist() && !reflect.DeepEqual(currentAfter, target) {
			return errNoPreciseMatch
		} else if target.IsBlacklist() != currentAfter.IsBlacklist() {
			return errNoMatch
		}
	}
	return nil
}

func loadEmulator(path string) (*devices.Emulator, error) {
	list, err := fscommon.ReadFile(path, "devices.list")
	if err != nil {
		return nil, err
	}
	return devices.EmulatorFromList(bytes.NewBufferString(list))
}

type v2DeviceController struct {
	closers                      map[string]func() error
	loadAttachCgroupDeviceFilter attachDeviceFilterFunc
}

func (v2 *v2DeviceController) UpdateBlockMajorMinor(major, minor int64, path string, allow, skipSafetyCheck bool) error {
	key := composeDeviceKey(major, minor, path)
	closer, exists := v2.closers[key]

	if allow {
		if exists {
			return fmt.Errorf("Device already whitelisted: %s", key)
		}
		deviceRule := newBlockDeviceRule(major, minor, allow)
		closer, err := v2.attachDeviceFilter(path, deviceRule)
		if err == nil {
			v2.closers[key] = closer
		}
		return err
	} else {
		if !exists {
			return fmt.Errorf("Device is not whitelisted: %s", key)
		}
		delete(v2.closers, key)
		return closer()
	}
}

func composeDeviceKey(major, minor int64, path string) string {
	return filepath.Join(path, fmt.Sprintf("%d:%d", major, minor))
}

// Based on setDevices from
//  https://github.com/opencontainers/runc/blob/ff819c7e9184c13b7c2607fe6c30ae19403a7aff/libcontainer/cgroups/fs2/devices.go#L40
func (v2 *v2DeviceController) attachDeviceFilter(path string, rule *configs.DeviceRule) (closer func() error, err error) {
	closer = func() error { return nil }

	insts, license, err := devicefilter.DeviceFilter([]*configs.DeviceRule{rule})
	if err != nil {
		return
	}

	dirFD, err := unix.Open(path, unix.O_DIRECTORY|unix.O_RDONLY, 0600)
	if err != nil {
		return
	}
	defer unix.Close(dirFD)

	return v2.loadAttachCgroupDeviceFilter(insts, license, dirFD)
}

func NewDeviceController() DeviceController {
	return newDeviceController(cgroups.IsCgroup2UnifiedMode(), ebpf.LoadAttachCgroupDeviceFilter)
}

func newDeviceController(isCgroup2UnifiedMode bool, loadAttachCgroupDeviceFilter attachDeviceFilterFunc) DeviceController {
	if isCgroup2UnifiedMode {
		return &v2DeviceController{
			closers:                      make(map[string]func() error),
			loadAttachCgroupDeviceFilter: loadAttachCgroupDeviceFilter,
		}
	}
	return &v1DeviceController{}
}
