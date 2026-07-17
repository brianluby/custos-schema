use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::base::Timestamp;
use crate::enums::ocsf_enum;
use crate::objects::{Product, User};

ocsf_enum! {
    /// Normalized file content confidentiality indicator (OCSF
    /// `file.confidentiality_id`).
    pub enum ConfidentialityId {
        NotConfidential = 1,
        Confidential = 2,
        Secret = 3,
        TopSecret = 4,
        Private = 5,
        Restricted = 6,
    }
}

ocsf_enum! {
    /// Normalized disk drive type (OCSF `file.drive_type_id`).
    pub enum DriveTypeId {
        Removable = 1,
        Fixed = 2,
        Remote = 3,
        CdRom = 4,
        RamDisk = 5,
    }
}

ocsf_enum! {
    /// Normalized file type (OCSF `file.type_id`).
    pub enum FileTypeId {
        RegularFile = 1,
        Folder = 2,
        CharacterDevice = 3,
        BlockDevice = 4,
        LocalSocket = 5,
        NamedPipe = 6,
        SymbolicLink = 7,
        ExecutableFile = 8,
    }
}

/// OCSF `file` object: describes the metadata associated with a file stored
/// in a computer system, including its attributes, properties, and
/// organizational details.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct File {
    /// The time when the file was last accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_time: Option<Timestamp>,
    /// `accessed_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed_time_dt: Option<String>,
    /// The name of the user who last accessed the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessor: Option<User>,
    /// The bitmask value that represents the file attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<i32>,
    /// The name of the company that published the file, e.g. `Microsoft Corporation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    /// The file content confidentiality, normalized to the caption of
    /// `confidentiality_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality: Option<String>,
    /// The normalized identifier of the file content confidentiality
    /// indicator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_id: Option<ConfidentialityId>,
    /// The time when the file was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<Timestamp>,
    /// `created_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<String>,
    /// The user that created the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<User>,
    /// The description of the file, as returned by the file system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// The drive type, normalized to the caption of the `drive_type_id`
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_type: Option<String>,
    /// Identifies the type of a disk drive, i.e. fixed, removable, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_type_id: Option<DriveTypeId>,
    /// The encryption details of the file. Should be populated if the file
    /// is encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_details: Option<serde_json::Value>,
    /// The extension of the file, excluding the leading dot, e.g. `exe`
    /// from `svchost.exe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
    /// An array of hash attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<serde_json::Value>>,
    /// A list of symbols imported by the executable file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported_symbols: Option<Vec<String>>,
    /// The name of the file as identified within the file itself. This
    /// contrasts with the name by which the file is known on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_name: Option<String>,
    /// Indicates if the file was deleted from the filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_deleted: Option<bool>,
    /// Indicates if the file is encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_encrypted: Option<bool>,
    /// Indicates if the file is publicly accessible, e.g. an object's
    /// public access in AWS S3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
    /// Indicates that the file cannot be modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_readonly: Option<bool>,
    /// The indication of whether the object is part of the operating
    /// system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_system: Option<bool>,
    /// The Multipurpose Internet Mail Extensions (MIME) type of the file,
    /// if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// The time when the file was last modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<Timestamp>,
    /// `modified_time` as RFC 3339 (datetime profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time_dt: Option<String>,
    /// The user that last modified the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier: Option<User>,
    /// The name of the file, e.g. `svchost.exe`.
    pub name: String,
    /// The user that owns the file/object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User>,
    /// The parent folder in which the file resides, e.g.
    /// `c:\windows\system32`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_folder: Option<String>,
    /// The full path to the file, e.g. `c:\windows\system32\svchost.exe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The product that created or installed the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// The object security descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_descriptor: Option<String>,
    /// The digital signature of the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<serde_json::Value>,
    /// A collection of `Digital Signature` objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<serde_json::Value>>,
    /// The size of data, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// The storage class of the file, e.g. in AWS S3: `STANDARD`,
    /// `STANDARD_IA`, `GLACIER`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// The list of tags; `{key:value}` pairs associated to the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<serde_json::Value>>,
    /// The file type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// The file type ID. Note the distinction between a `Regular File` and
    /// an `Executable File`. If the distinction is not known, `Regular
    /// File` should be used.
    pub type_id: FileTypeId,
    /// The unique identifier of the file as defined by the storage system,
    /// such as the file system file ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The file URI, such as those reported by static analysis tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// The URL of the file, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<serde_json::Value>,
    /// The file version, e.g. `8.0.7601.17514`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The volume on the storage device where the file is located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// An unordered collection of zero or more name/value pairs where each
    /// pair represents a file or folder extended attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xattributes: Option<serde_json::Value>,
    /// Unknown/future fields, preserved losslessly.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidentiality_id_roundtrips_known_and_unrecognized() {
        assert_eq!(ConfidentialityId::from(4), ConfidentialityId::TopSecret);
        assert_eq!(ConfidentialityId::from(0), ConfidentialityId::Unknown);
        assert_eq!(
            ConfidentialityId::from(1234),
            ConfidentialityId::Unrecognized(1234)
        );
    }

    #[test]
    fn drive_type_id_roundtrips_known_and_unrecognized() {
        assert_eq!(DriveTypeId::from(4), DriveTypeId::CdRom);
        assert_eq!(DriveTypeId::from(0), DriveTypeId::Unknown);
        assert_eq!(DriveTypeId::from(1234), DriveTypeId::Unrecognized(1234));
    }

    #[test]
    fn file_type_id_roundtrips_known_and_unrecognized() {
        assert_eq!(FileTypeId::from(8), FileTypeId::ExecutableFile);
        assert_eq!(FileTypeId::from(0), FileTypeId::Unknown);
        assert_eq!(FileTypeId::from(1234), FileTypeId::Unrecognized(1234));
    }

    #[test]
    fn file_roundtrips_unknown_fields() {
        let json = r#"{"name":"svchost.exe","type_id":8,"future_field":1}"#;
        let file: File = serde_json::from_str(json).unwrap();
        assert_eq!(file.name, "svchost.exe");
        assert_eq!(file.type_id, FileTypeId::ExecutableFile);
        assert_eq!(file.other["future_field"], 1);
        let out = serde_json::to_value(&file).unwrap();
        assert_eq!(out["future_field"], 1);
        assert!(out.get("uid").is_none());
    }
}
