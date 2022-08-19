package recorder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	v1 "kubevirt.io/api/core/v1"

	diskutils "kubevirt.io/kubevirt/pkg/ephemeral-disk-utils"
	"kubevirt.io/kubevirt/pkg/safepath"
	"kubevirt.io/kubevirt/pkg/unsafepath"
)

//go:generate mockgen -source $GOFILE -package=$GOPACKAGE -destination=generated_mock_$GOFILE
type MountTargetEntry struct {
	TargetFile string `json:"targetFile"`
	SocketFile string `json:"socketFile,omitempty"`
}

type VMIMountTargetRecord struct {
	HotpluggedVolumes []MountTargetEntry `json:"hotpluggedDisks"`
	ContainerDisks    []MountTargetEntry `json:"containerDisks"`
	UsesSafePaths     bool               `json:"usesSafePaths"`
}

func (r *VMIMountTargetRecord) GetContainerDisks() []MountTargetEntry {
	return r.ContainerDisks
}

func (r *VMIMountTargetRecord) GetHotpluggedVolumes() []MountTargetEntry {
	return r.HotpluggedVolumes
}

func isRecordEmpty(record *VMIMountTargetRecord) bool {
	if record == nil {
		return true
	}
	return len(record.ContainerDisks) == 0 && len(record.HotpluggedVolumes) == 0
}

const (
	ContainerDiskMountStates     = "container-disk-mount-state"
	HotpluggedVolumesMountStates = "hotplug-volume-mount-state"
)

type vmiMountTargetRecordForCache struct {
	MountTargetEntries []MountTargetEntry `json:"mountTargetEntries"`
	UsesSafePaths      bool               `json:"usesSafePaths"`
}

func readRecordFile(recordFile string) ([]MountTargetEntry, bool, error) {
	record := vmiMountTargetRecordForCache{}
	// #nosec No risk for path injection. Using static base and cleaned filename
	bytes, err := os.ReadFile(recordFile)
	if err != nil {
		return []MountTargetEntry{}, false, err
	}
	err = json.Unmarshal(bytes, &record)
	if err != nil {
		return []MountTargetEntry{}, false, err
	}
	return record.MountTargetEntries, record.UsesSafePaths, nil
}

func (m *mounter) ReadRecordFiles(uid string) (*VMIMountTargetRecord, bool, error) {
	record := &VMIMountTargetRecord{}
	var useSafepathsCd, useSafepathsHp bool
	// Read the container disks entries from the filesystem
	// if not there, see if record is on disk, this can happen if virt-handler restarts
	recordFile := filepath.Join(m.mountStateDir, ContainerDiskMountStates, filepath.Clean(uid))
	existsCds, err := diskutils.FileExists(recordFile)
	if err != nil {
		return nil, false, err
	}
	if existsCds {
		record.ContainerDisks, useSafepathsCd, err = readRecordFile(recordFile)
		if err != nil {
			return nil, false, err
		}
	}

	// Read hotplugged volumes entries from the filesystem
	recordFile = filepath.Join(m.mountStateDir, HotpluggedVolumesMountStates, filepath.Clean(uid))
	if err != nil {
		return nil, false, err
	}
	existsHps, err := diskutils.FileExists(recordFile)
	if err != nil {
		return nil, false, err
	}
	if existsHps {
		record.HotpluggedVolumes, useSafepathsHp, err = readRecordFile(recordFile)
		if err != nil {
			return nil, false, err
		}
	}
	record.UsesSafePaths = useSafepathsHp && useSafepathsCd
	return record, existsCds || existsHps, nil
}

func writeRecordFile(recordFile string, record []MountTargetEntry) error {
	r := vmiMountTargetRecordForCache{
		MountTargetEntries: record,
		// XXX: backward compatibility for old unresolved paths, can be removed in July 2023
		// After a one-time convert and persist, old records are safe too.
		UsesSafePaths: true,
	}
	bytes, err := json.Marshal(r)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(recordFile), 0750)
	if err != nil {
		return err
	}

	return os.WriteFile(recordFile, bytes, 0600)
}

func (m *mounter) WriteRecordFiles(uid string, record *VMIMountTargetRecord) error {
	errCd := writeRecordFile(filepath.Join(m.mountStateDir, ContainerDiskMountStates, uid), record.ContainerDisks)
	errHp := writeRecordFile(filepath.Join(m.mountStateDir, HotpluggedVolumesMountStates, uid), record.HotpluggedVolumes)
	return wrapErrors(errCd, errHp)
}

type RecordEntry int

const (
	CONTAINERDISKS_ENTRY RecordEntry = iota
	HOTPLUGGEDVOLUMES_ENTRY
	ALL_ENTRIES
)

type mounter struct {
	mountStateDir    string
	mountRecords     map[types.UID]*VMIMountTargetRecord
	mountRecordsLock sync.Mutex
}

type MountRecorder interface {
	SetAddMountRecordContainerDisk(vmi *v1.VirtualMachineInstance, cdRecord []MountTargetEntry, addPreviousRules bool) error
	DeleteContainerDisksMountRecord(vmi *v1.VirtualMachineInstance) error
	GetContainerDisksMountRecord(vmi *v1.VirtualMachineInstance) ([]MountTargetEntry, error)
	SetMountRecordHotpluggedVolumes(vmi *v1.VirtualMachineInstance, hpRecord []MountTargetEntry) error
	GetHotpluggedVolumesMountRecord(vmi *v1.VirtualMachineInstance) ([]MountTargetEntry, error)
	DeleteHotpluggedVolumesMountRecord(vmi *v1.VirtualMachineInstance) error
	ReadRecordFiles(uid string) (*VMIMountTargetRecord, bool, error)
	WriteRecordFiles(uid string, record *VMIMountTargetRecord) error
}

func NewMountRecorder(mountStateDir string) MountRecorder {
	return &mounter{
		mountStateDir: mountStateDir,
		mountRecords:  make(map[types.UID]*VMIMountTargetRecord),
	}
}

func (m *mounter) SetAddMountRecordContainerDisk(vmi *v1.VirtualMachineInstance, cdRecord []MountTargetEntry, addPreviousRules bool) error {
	record, err := m.getMountTargetRecord(vmi)
	if err != nil {
		return err
	}

	if addPreviousRules {
		record.ContainerDisks = append(record.ContainerDisks, cdRecord...)
	} else {
		record.ContainerDisks = cdRecord
	}

	return m.setMountTargetRecord(vmi, record)
}

func (m *mounter) SetMountRecordHotpluggedVolumes(vmi *v1.VirtualMachineInstance, hpRecord []MountTargetEntry) error {
	record, err := m.getMountTargetRecord(vmi)
	if err != nil {
		return err
	}
	record.HotpluggedVolumes = hpRecord

	return m.setMountTargetRecord(vmi, record)
}

func (m *mounter) DeleteContainerDisksMountRecord(vmi *v1.VirtualMachineInstance) error {
	return m.deleteMountTargetRecord(vmi, CONTAINERDISKS_ENTRY)
}

func (m *mounter) DeleteHotpluggedVolumesMountRecord(vmi *v1.VirtualMachineInstance) error {
	return m.deleteMountTargetRecord(vmi, HOTPLUGGEDVOLUMES_ENTRY)
}

func (m *mounter) GetContainerDisksMountRecord(vmi *v1.VirtualMachineInstance) ([]MountTargetEntry, error) {
	record, err := m.getMountTargetRecord(vmi)
	if err != nil {
		return []MountTargetEntry{}, err
	}
	if record == nil {
		return []MountTargetEntry{}, nil
	}
	return record.GetContainerDisks(), nil
}

func (m *mounter) GetHotpluggedVolumesMountRecord(vmi *v1.VirtualMachineInstance) ([]MountTargetEntry, error) {
	record, err := m.getMountTargetRecord(vmi)
	if err != nil {
		return []MountTargetEntry{}, err
	}
	return record.GetHotpluggedVolumes(), nil
}

func deleteMountTargetRecordFile(vmi *v1.VirtualMachineInstance, recordFile string, entries []MountTargetEntry) error {
	exists, err := diskutils.FileExists(recordFile)
	if err != nil {
		return err
	}

	if exists {
		for _, target := range entries {
			os.Remove(target.TargetFile)
			os.Remove(target.SocketFile)
		}

		os.Remove(recordFile)
	}

	return nil
}

func (m *mounter) deleteMountTargetRecord(vmi *v1.VirtualMachineInstance, entry RecordEntry) error {
	if string(vmi.UID) == "" {
		return fmt.Errorf("cannot find the mount record without the VMI uid")
	}

	record, err := m.getMountTargetRecord(vmi)
	if err != nil {
		return err
	}

	r, ok := m.mountRecords[vmi.UID]
	var errCd, errHp error

	if entry == CONTAINERDISKS_ENTRY || entry == ALL_ENTRIES {
		errCd = deleteMountTargetRecordFile(vmi, filepath.Join(m.mountStateDir, ContainerDiskMountStates, string(vmi.UID)), record.ContainerDisks)
		if ok {
			r.ContainerDisks = []MountTargetEntry{}
		}
	}
	if entry == HOTPLUGGEDVOLUMES_ENTRY || entry == ALL_ENTRIES {
		errHp = deleteMountTargetRecordFile(vmi, filepath.Join(m.mountStateDir, HotpluggedVolumesMountStates, string(vmi.UID)), record.HotpluggedVolumes)
		if ok {
			r.HotpluggedVolumes = []MountTargetEntry{}
		}
	}
	if isRecordEmpty(r) {
		m.mountRecordsLock.Lock()
		defer m.mountRecordsLock.Unlock()
		delete(m.mountRecords, vmi.UID)
	} else {
		m.mountRecords[vmi.UID] = r
		m.setMountTargetRecord(vmi, r)
	}
	return wrapErrors(errCd, errHp)
}

func (m *mounter) getMountTargetRecord(vmi *v1.VirtualMachineInstance) (*VMIMountTargetRecord, error) {
	var ok bool
	var existingRecord *VMIMountTargetRecord

	if string(vmi.UID) == "" {
		return &VMIMountTargetRecord{}, fmt.Errorf("unable to find container disk mounted directories for vmi without uid")
	}

	m.mountRecordsLock.Lock()
	defer m.mountRecordsLock.Unlock()
	existingRecord, ok = m.mountRecords[vmi.UID]

	// first check memory cache
	if ok {
		return existingRecord, nil
	}

	record, exists, err := m.ReadRecordFiles(string(vmi.UID))
	if err != nil {
		return &VMIMountTargetRecord{}, err
	}
	if exists {
		// XXX: backward compatibility for old unresolved paths, can be removed in July 2023
		// After a one-time convert and persist, old records are safe too.
		if !record.UsesSafePaths {
			record.UsesSafePaths = true
			for i, entry := range record.ContainerDisks {
				safePath, err := safepath.JoinAndResolveWithRelativeRoot("/", entry.TargetFile)
				if err != nil {
					return &VMIMountTargetRecord{}, fmt.Errorf("failed converting legacy path to safepath: %v", err)
				}
				record.ContainerDisks[i].TargetFile = unsafepath.UnsafeAbsolute(safePath.Raw())
			}
			for i, entry := range record.HotpluggedVolumes {
				safePath, err := safepath.JoinAndResolveWithRelativeRoot("/", entry.TargetFile)
				if err != nil {
					return &VMIMountTargetRecord{}, fmt.Errorf("failed converting legacy path to safepath: %v", err)
				}
				record.HotpluggedVolumes[i].TargetFile = unsafepath.UnsafeAbsolute(safePath.Raw())
			}
		}

		m.mountRecords[vmi.UID] = record
		return record, nil
	}

	// not found
	return &VMIMountTargetRecord{}, nil
}

func (m *mounter) setMountTargetRecord(vmi *v1.VirtualMachineInstance, record *VMIMountTargetRecord) error {
	if string(vmi.UID) == "" {
		return fmt.Errorf("unable to find mounted directories for vmi without uid")
	}
	m.mountRecordsLock.Lock()
	defer m.mountRecordsLock.Unlock()

	if err := m.WriteRecordFiles(string(vmi.UID), record); err != nil {
		return err
	}

	m.mountRecords[vmi.UID] = record
	return nil
}

func wrapErrors(e1, e2 error) error {
	if e1 == nil {
		return e2
	}
	if e2 != nil {
		return errors.Wrap(e1, e2.Error())
	}
	return e1
}
