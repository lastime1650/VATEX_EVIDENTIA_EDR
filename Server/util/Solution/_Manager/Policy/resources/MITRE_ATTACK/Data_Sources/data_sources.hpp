#ifndef MITRE_ATTACK_DATA_SOURCES_HPP
#define MITRE_ATTACK_DATA_SOURCES_HPP

#include <cstdint>

namespace MITRE_ATTACK
{
    namespace DATA_SOURCES
    {
        /*
            ref : https://attack.mitre.org/datasources
            이벤트 유형 정의
        */
       enum class DataSource : std::uint32_t {
            ActiveDirectory,
            ActiveDirectoryCredentialRequest,
            ActiveDirectoryObjectAccess,
            ActiveDirectoryObjectCreation,
            ActiveDirectoryObjectDeletion,
            ActiveDirectoryObjectModification,

            ApplicationLog,
            ApplicationLogContent,
            ApplicationLogVetting,

            APICalls,
            ApplicationAssets,
            NetworkCommunication,
            PermissionsRequests,
            ProtectedConfiguration,
            Asset,
            AssetInventory,
            Software,
            Certificate,
            CertificateRegistration,

            CloudService,
            CloudServiceDisable,
            CloudServiceEnumeration,
            CloudServiceMetadata,
            CloudServiceModification,

            CloudStorage,
            CloudStorageAccess,
            CloudStorageCreation,
            CloudStorageDeletion,
            CloudStorageEnumeration,
            CloudStorageMetadata,
            CloudStorageModification,

            Command,
            CommandExecution,

            Container,
            ContainerCreation,
            ContainerEnumeration,
            ContainerStart,

            DomainName,
            DomainNameActiveDNS,
            DomainNameDomainRegistration,
            DomainNamePassiveDNS,

            Drive,
            DriveAccess,
            DriveCreation,
            DriveModification,

            Driver,
            DriverLoad,
            DriverMetadata,

            File,
            FileAccess,
            FileCreation,
            FileDeletion,
            FileMetadata,
            FileModification,

            Firewall,
            FirewallDisable,
            FirewallEnumeration,
            FirewallMetadata,
            FirewallRuleModification,

            Firmware,
            FirmwareModification,

            Group,
            GroupEnumeration,
            GroupMetadata,
            GroupModification,

            Image,
            ImageCreation,
            ImageDeletion,
            ImageMetadata,
            ImageModification,

            Instance,
            InstanceCreation,
            InstanceDeletion,
            InstanceEnumeration,
            InstanceMetadata,
            InstanceModification,
            InstanceStart,
            InstanceStop,

            InternetScan,
            ResponseContent,
            ResponseMetadata,

            Kernel,
            KernelModuleLoad,

            LogonSession,
            LogonSessionCreation,
            LogonSessionMetadata,

            MalwareRepository,
            MalwareRepositoryContent,
            MalwareRepositoryMetadata,

            Module,
            ModuleLoad,

            NamedPipe,
            NamedPipeMetadata,

            NetworkShare,
            NetworkShareAccess,

            NetworkTraffic,
            NetworkConnectionCreation,
            NetworkTrafficContent,
            NetworkTrafficFlow,

            OperationalDatabases,
            DeviceAlarm,
            ProcessHistoryLiveData,
            ProcessEventAlarm,

            Persona,
            SocialMedia,

            Pod,
            PodCreation,
            PodEnumeration,
            PodModification,

            Process,
            ProcessOSAPIExecution,
            ProcessAccess,
            ProcessCreation,
            ProcessMetadata,
            ProcessModification,
            ProcessTermination,

            ScheduledJob,
            ScheduledJobCreation,
            ScheduledJobMetadata,
            ScheduledJobModification,

            Script,
            ScriptExecution,

            SensorHealth,
            HostStatus,

            Service,
            ServiceCreation,
            ServiceMetadata,
            ServiceModification,

            Snapshot,
            SnapshotCreation,
            SnapshotDeletion,
            SnapshotEnumeration,
            SnapshotMetadata,
            SnapshotModification,

            UserAccount,
            UserAccountAuthentication,
            UserAccountCreation,
            UserAccountDeletion,
            UserAccountMetadata,
            UserAccountModification,

            UserInterface,
            PermissionsRequest,
            SystemNotifications,
            SystemSettings,

            Volume,
            VolumeCreation,
            VolumeDeletion,
            VolumeEnumeration,
            VolumeMetadata,
            VolumeModification,

            WebCredential,
            WebCredentialCreation,
            WebCredentialUsage,

            WindowsRegistry,
            WindowsRegistryKeyAccess,
            WindowsRegistryKeyCreation,
            WindowsRegistryKeyDeletion,
            WindowsRegistryKeyModification,

            WMI,
            WMICreation,

            Unknown
        };

    }
}

#endif