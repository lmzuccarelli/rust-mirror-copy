use async_trait::async_trait;
use custom_logger::*;
use hex::encode;
use mirror_error::MirrorError;
use reqwest::{Client, StatusCode};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha256::digest;
use std::fs;
use std::os::unix::fs::MetadataExt;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub media_type: String,
    pub size: i64,
    pub digest: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: Option<i64>,

    #[serde(rename = "digest")]
    pub digest: Option<String>,

    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,

    #[serde(rename = "platform")]
    pub platform: Option<ManifestPlatform>,

    #[serde(rename = "size")]
    pub size: Option<i64>,

    #[serde(rename = "config")]
    pub config: Option<Layer>,

    #[serde(rename = "layers")]
    pub layers: Option<Vec<Layer>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestPlatform {
    #[serde(rename = "architecture")]
    pub architecture: String,

    #[serde(rename = "os")]
    pub os: String,
}

#[derive(Debug, Clone)]
pub struct ImplDownloadImageInterface {}

#[async_trait]
pub trait DownloadImageInterface {
    // used to interact with container registry (manifest calls)
    // this seems strange to expose the get manifest and get blobs
    // rather than just get images (as in push_image)
    // the separation is to allow for more flexibility in just querying (getting)
    // manifests and then based on the response, we can decide to download blobs
    async fn get_manifest(&self, url: String, token: String) -> Result<String, MirrorError>;
    // get a single blob
    async fn get_blob(
        &self,
        log: &Logging,
        dir: String,
        url: String,
        token: String,
        verify_blob: bool,
        blob_sum: String,
    ) -> Result<(), MirrorError>;
}

#[async_trait]
impl DownloadImageInterface for ImplDownloadImageInterface {
    async fn get_manifest(&self, url: String, token: String) -> Result<String, MirrorError> {
        let client = Client::new();
        // check without token
        if token.len() == 0 {
            let res  = client
                .get(url)
                .header("Accept", "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json")
                .header("Content-Type", "application/json")
                .send()
                .await;
            if res.is_ok() {
                let body = res.unwrap().text().await;
                if body.is_ok() {
                    Ok(body.unwrap())
                } else {
                    let err = MirrorError::new(&format!(
                        "[get_manifest] could not read body contents {}",
                        body.err().unwrap().to_string().to_lowercase()
                    ));
                    Err(err)
                }
            } else {
                let err = MirrorError::new(&format!(
                    "[get_manifest] could not read body contents {}",
                    res.err().unwrap().to_string().to_lowercase()
                ));
                Err(err)
            }
        } else {
            let mut header_bearer: String = "Bearer ".to_owned();
            header_bearer.push_str(&token);
            let res = client
            .get(url)
            .header("Accept", "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json")
            .header("Content-Type", "application/json")
            .header("Authorization", header_bearer)
            .send()
            .await;

            if res.is_ok() {
                let body = res.unwrap().text().await;
                if body.is_ok() {
                    Ok(body.unwrap())
                } else {
                    let err = MirrorError::new(&format!(
                        "[get_manifest] could not read body contents {}",
                        body.err().unwrap().to_string().to_lowercase()
                    ));
                    Err(err)
                }
            } else {
                let err = MirrorError::new(&format!(
                    "[get_manifest] could not read body contents {}",
                    res.err().unwrap().to_string().to_lowercase()
                ));
                Err(err)
            }
        }
    }
    // get a single blob
    async fn get_blob(
        &self,
        log: &Logging,
        dir: String,
        url: String,
        token: String,
        verify_blob: bool,
        blob_sum: String,
    ) -> Result<(), MirrorError> {
        let client = Client::new();
        let header_bearer = format!("Bearer {}", token.clone());
        let inner_url = format!("{}{}", url.clone(), blob_sum);
        let res = client
            .get(inner_url.clone())
            .header("Authorization", header_bearer)
            .send()
            .await;
        if res.is_ok() {
            let body = res.unwrap().bytes().await;
            if body.is_ok() {
                if !blob_sum.contains("sha256:") {
                    let err = MirrorError::new("blob sha sum format seems to be incorrect");
                    return Err(err);
                }
                let blob_digest = blob_sum.split(":").nth(1).unwrap();
                let msg = format!("  writing blob {}", blob_digest);
                log.ex(&msg);
                let blob_dir = format!("{}/{}", dir.clone(), &blob_digest[0..2]);
                let res = fs::create_dir_all(blob_dir.clone());
                if res.is_err() {
                    let err = MirrorError::new(&format!(
                        "blob dir {} {}",
                        blob_dir,
                        res.err().unwrap().to_string().to_lowercase()
                    ));
                    return Err(err);
                }
                let data = body.unwrap();
                if verify_blob {
                    let hash = digest(data.to_vec());
                    if hash != blob_digest {
                        let err = MirrorError::new(&format!(
                            "blob sum error {} url {}",
                            blob_digest,
                            url.clone()
                        ));
                        return Err(err);
                    }
                }
                if res.is_err() {
                    let err = MirrorError::new(&format!(
                        "creating blob directory {}",
                        res.err().unwrap().to_string().to_lowercase()
                    ));
                    return Err(err);
                }
                let full_dir = format!("{}/{}", blob_dir.clone(), blob_digest);
                let res_w = fs::write(full_dir.clone(), data);
                if res_w.is_err() {
                    let err = MirrorError::new(&format!(
                        "writing blob data {}",
                        res_w.err().unwrap().to_string().to_lowercase()
                    ));
                    return Err(err);
                }
                println!("\x1b[1A \x1b[38C{}", "\x1b[1;92m✓\x1b[0m");
            } else {
                println!("\x1b[1A \x1b[38C{}", "\x1b[1;91m✗\x1b[0m");
                let err = MirrorError::new(&format!(
                    "reading body contents (fetch blob) {}",
                    body.err().unwrap().to_string().to_lowercase()
                ));
                return Err(err);
            }
        } else {
            println!("\x1b[1A \x1b[38C{}", "\x1b[1;91m✗\x1b[0m");
            let err = MirrorError::new(&format!(
                "api call (fetch blob) {}",
                res.err().unwrap().to_string().to_lowercase()
            ));
            return Err(err);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ImplUploadImageInterface {}

#[async_trait]
pub trait UploadImageInterface {
    async fn process_manifests(
        &self,
        log: &Logging,
        url: String,
        namespace: String,
        manifest: Manifest,
        tag_digest: String,
        token: String,
    ) -> Result<String, MirrorError>;

    async fn check_manifest(
        &self,
        log: &Logging,
        url: String,
        namespace: String,
        tag_digest: String,
        token: String,
    ) -> Result<String, MirrorError>;

    async fn process_blob(
        &self,
        log: &Logging,
        url: String,
        namespace: String,
        dir: String,
        skip_verify: bool,
        blob: String,
        token: String,
    ) -> Result<String, MirrorError>;
}

#[async_trait]
impl UploadImageInterface for ImplUploadImageInterface {
    async fn process_manifests(
        &self,
        _log: &Logging,
        url: String,
        namespace: String,
        manifest: Manifest,
        tag_digest: String,
        token: String,
    ) -> Result<String, MirrorError> {
        let client = Client::new();
        let client = client.clone();
        let mut header_bearer: String = "Bearer ".to_owned();
        header_bearer.push_str(&token);

        // finally push the manifest
        let serialized_manifest = serde_json::to_string(&manifest.clone()).unwrap();

        let put_url = format!(
            "https://{}/v2/{}/manifests/",
            url.clone(),
            namespace.clone(),
        );

        let str_digest: String;
        if tag_digest == "".to_string() {
            let mut hasher = Sha256::new();
            hasher.update(serialized_manifest.clone());
            let hash_bytes = hasher.finalize();
            str_digest = encode(hash_bytes);
        } else {
            str_digest = tag_digest.replace(":", "-");
        }
        let res_put = client
            .put(put_url.clone() + &str_digest.clone())
            .body(serialized_manifest.clone())
            .header("Authorization", header_bearer)
            .header(
                "Content-Type",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .header("Content-Length", serialized_manifest.len())
            .send()
            .await;

        let result = res_put.unwrap();
        if result.status() != StatusCode::CREATED && result.status() != StatusCode::OK {
            let err = MirrorError::new(&format!(
                "[process_manifests] upload manifest failed with status {} : {}",
                result.status(),
                result.text().await.unwrap().to_string()
            ));
            Err(err)
        } else {
            Ok(String::from("ok"))
        }
    }
    async fn check_manifest(
        &self,
        _log: &Logging,
        url: String,
        namespace: String,
        tag_digest: String,
        token: String,
    ) -> Result<String, MirrorError> {
        let client = Client::new();
        let client = client.clone();
        let header_bearer = format!("Bearer {}", token);

        let head_url = format!(
            "https://{}/v2/{}/manifests/{}",
            url.clone(),
            namespace.clone(),
            tag_digest,
        );

        let res_head = client
            .head(head_url.clone())
            .header("Accept", "application/json")
            .header("Authorization", header_bearer)
            .send()
            .await;

        if res_head.is_ok() {
            let result = res_head.unwrap();
            if result.status() != StatusCode::OK {
                let err = MirrorError::new(&format!(
                    "upload manifest failed with status {}",
                    result.status(),
                ));
                Err(err)
            } else {
                Ok(String::from("ok"))
            }
        } else {
            let err = MirrorError::new(&format!(
                "[check_manifest] upload manifest failed {}",
                res_head.err().unwrap().to_string().to_lowercase(),
            ));
            Err(err)
        }
    }
    async fn process_blob(
        &self,
        log: &Logging,
        url: String,
        namespace: String,
        dir: String,
        verify_blobs: bool,
        blob: String,
        token: String,
    ) -> Result<String, MirrorError> {
        let client = Client::new();
        let client = client.clone();
        let mut header_bearer: String = "Bearer ".to_owned();
        header_bearer.push_str(&token);

        let head_url = format!(
            "https://{}/v2/{}/blobs/sha256:{}",
            url.clone(),
            namespace.clone(),
            blob.clone()
        );

        let res_head = client
            .head(head_url.clone())
            .header("Authorization", header_bearer.clone())
            .send()
            .await;

        if res_head.unwrap().status() == StatusCode::NOT_FOUND {
            let post_url = format!(
                "https://{}/v2/{}/blobs/uploads/",
                url.clone(),
                namespace.clone(),
            );

            let res = client
                .post(post_url.clone())
                .header("Authorization", header_bearer.clone())
                .send()
                .await;

            if res.is_ok() {
                if res.as_ref().unwrap().status() != StatusCode::ACCEPTED {
                    let err = MirrorError::new(&format!(
                        "initial post failed with status {:#?}",
                        res.unwrap().status()
                    ));
                    return Err(err);
                }
            } else {
                let err = MirrorError::new(&format!(
                    "{}",
                    res.err().unwrap().to_string().to_lowercase()
                ));
                return Err(err);
            }

            let response = res.unwrap();
            let location = response.headers().get("Location").unwrap();

            let res_patch = client
                .patch(location.to_str().unwrap())
                .header("Authorization", header_bearer.clone())
                .header("Accept", "application/json")
                .send()
                .await;

            let res_response = res_patch.unwrap();

            if res_response.status() == StatusCode::ACCEPTED {
                let mut file = File::open(dir.clone() + &"/" + &blob).await.unwrap();
                let mut vec_bytes = Vec::new();
                let _buf = file.read_to_end(&mut vec_bytes).await.unwrap();
                if verify_blobs {
                    let res = verify_file(
                        log,
                        dir.clone(),
                        blob.clone(),
                        vec_bytes.len() as u64,
                        vec_bytes.clone(),
                    )
                    .await;
                    if res.is_err() {
                        let err = MirrorError::new(&format!("{}", res.err().unwrap().to_string(),));
                        return Err(err);
                    }
                }
                let url = location.to_str().unwrap().to_string() + &"?digest=sha256:" + &blob;

                let res_put = client
                    .put(url)
                    .body(vec_bytes.clone())
                    .header("Authorization", header_bearer.clone())
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", vec_bytes.len())
                    .send()
                    .await;

                let res_final = res_put.unwrap();

                if res_final.status() > StatusCode::CREATED {
                    let err = MirrorError::new(&format!(
                        "[process_blob] put blob failed with code {} : message {:#?}",
                        res_final.status(),
                        res_final.text().await.unwrap().to_string()
                    ));
                    return Err(err);
                }
            }
        }
        Ok(String::from("ok"))
    }
}

// verify_file - function to check size and sha256 hash of contents
async fn verify_file(
    _log: &Logging,
    dir: String,
    blob_sum: String,
    blob_size: u64,
    data: Vec<u8>,
) -> Result<(), MirrorError> {
    let f = &format!("{}/{}", dir, blob_sum);
    let res = fs::metadata(&f);
    if res.is_ok() {
        if res.unwrap().size() != blob_size {
            let err = MirrorError::new(&format!(
                "sha256 file size don't match {}",
                blob_size.clone()
            ));
            return Err(err);
        }
        let hash = digest(&data);
        if hash != blob_sum {
            let err = MirrorError::new(&format!(
                "sha256 hash contents don't match {} {}",
                hash,
                blob_sum.clone()
            ));
            return Err(err);
        }
    } else {
        let err = MirrorError::new(&format!("sha256 hash metadata file {}", f));
        return Err(err);
    }
    Ok(())
}

/*
// get the formatted destination registry (from command line)
pub fn get_destination_registry(url: String, component: String, mode: String) -> String {
    let mut hld = url.split("docker://");
    let reg_str = hld.nth(1).unwrap();
    let mut name_str = reg_str.split("/");
    let mut reg = DestinationRegistry {
        protocol: String::from("http://"),
        registry: name_str.nth(0).unwrap().to_string(),
        name: name_str.nth(0).unwrap().to_string(),
    };

    match mode.as_str() {
        "https_blobs_uploads" => {
            reg.protocol = String::from("https://");
            return reg.protocol
                + &reg.registry
                + &"/v2/"
                + &reg.name
                + &"/"
                + &component
                + &"/blobs/uploads/";
        }
        "http_blobs_uploads" => {
            return reg.protocol
                + &reg.registry
                + &"/v2/"
                + &reg.name
                + &"/"
                + &component
                + &"/blobs/uploads/"
        }
        "http_blobs_digest" => {
            return reg.protocol
                + &reg.registry
                + &"/v2/"
                + &reg.name
                + &"/"
                + &component
                + &"/blobs/"
        }
        "http_manifest" => {
            return reg.protocol
                + &reg.registry
                + &"/v2/"
                + &reg.name
                + &"/"
                + &component
                + &"/manifests/"
        }
        _ => {
            return reg.protocol
                + &reg.registry
                + &"/v2/"
                + &reg.name
                + "/"
                + &component
                + &"/blobs/uploads/"
        }
    };
}
    */

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    // this brings everything from parent's scope into this scope
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }
    #[test]
    fn fs_verify_file_pass() {
        let log = &Logging {
            log_level: Level::INFO,
        };

        macro_rules! aw {
            ($e:expr) => {
                tokio_test::block_on($e)
            };
        }

        let data = fs::read_to_string(
            "test-artifacts/c9e9e89d3e43c791365ec19dc5acd1517249a79c09eb482600024cd1c6475abe",
        )
        .expect("should read file");

        let res = aw!(verify_file(
            log,
            "test-artifacts".to_string(),
            "c9e9e89d3e43c791365ec19dc5acd1517249a79c09eb482600024cd1c6475abe".to_string(),
            504,
            data.into_bytes()
        ));
        if res.is_err() {
            log.error(&format!(
                "result -> {}",
                res.as_ref().err().unwrap().to_string().to_lowercase()
            ));
        }
        assert_eq!(res.is_ok(), true);
    }
    #[test]
    fn fs_verify_file_fail() {
        let log = &Logging {
            log_level: Level::INFO,
        };

        macro_rules! aw {
            ($e:expr) => {
                tokio_test::block_on($e)
            };
        }

        let data = fs::read_to_string(
            "test-artifacts/c9e9e89d3e43c791365ec19dc5acd1517249a79c09eb482600024cd1c6475abe",
        )
        .expect("should read file");

        let res = aw!(verify_file(
            log,
            "test-artifacts".to_string(),
            "c9e9e89d3e43c791365ec19dc5acd1517249a79c09eb482600024cd1c6475abe".to_string(),
            100,
            data.clone().into_bytes()
        ));
        if res.is_err() {
            log.error(&format!(
                "result -> {}",
                res.as_ref().err().unwrap().to_string().to_lowercase()
            ));
        }
        assert_eq!(res.is_err(), true);

        let res = aw!(verify_file(
            log,
            "test-artifacts".to_string(),
            "sha256:65e311ef7036acc3692d291403656b840fd216d120b3c37af768f91df050257d".to_string(),
            428,
            data.clone().into_bytes()
        ));
        if res.is_err() {
            log.error(&format!(
                "result -> {}",
                res.as_ref().err().unwrap().to_string().to_lowercase()
            ));
        }
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn get_manifest_pass() {
        let mut server = mockito::Server::new();
        let url = server.url();

        // Create a mock
        server
            .mock("GET", "/manifests")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{ \"test\": \"hello-world\" }")
            .create();

        let real = ImplDownloadImageInterface {};

        let res = aw!(real.get_manifest(url + "/manifests", String::from("token")));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), String::from("{ \"test\": \"hello-world\" }"));
    }

    /*
    #[test]
    fn get_blobs_pass() {
        let mut server = mockito::Server::new();
        let url = server.url();

        // Create a mock
        server
            .mock("GET", "/sha256:1234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{ \"test\": \"hello-world\" }")
            .create();

        let fslayer = FsLayer {
            blob_sum: String::from("sha256:1234567890"),
            original_ref: Some(url.clone()),
            size: Some(112),
            number: None,
        };
        let fslayers = vec![fslayer];
        let log = &Logging {
            log_level: Level::INFO,
        };

        let fake = ImplRegistryInterface {};

        // test with url set first
        aw!(fake.get_blobs(
            log,
            String::from("test-artifacts/test-blobs-store/"),
            url.clone() + "/",
            String::from("token"),
            fslayers.clone(),
        ));
        // check the file contents
        let s = fs::read_to_string("test-artifacts/test-blobs-store/12/1234567890")
            .expect("should read file");
        assert_eq!(s, "{ \"test\": \"hello-world\" }");
        fs::remove_dir_all("test-artifacts/test-blobs-store").expect("should delete");
    }

    #[test]
    fn push_image_pass() {
        let mut server = mockito::Server::new();
        let url = server.url();

        // Create a mock
        server
            .mock("POST", "/v2/test/test-component/blobs/uploads/")
            .with_status(202)
            .with_header(
                "Location",
                &(url.clone() + "/v2/test/test-component/blobs/uploads?uuid=21321321323"),
            )
            .create();

        server
            .mock("HEAD", "/v2/test/test-component/blobs/sha256:1b594048db9380f9a8dd2e45e16a2e12d39df51f6f61d9be4c9a2986cbc2828b")
            .with_status(404)
            .create();

        server
            .mock("PUT", "/v2/test/test-component/blobs/uploads?uuid=21321321323&digest=sha256:1b594048db9380f9a8dd2e45e16a2e12d39df51f6f61d9be4c9a2986cbc2828b")
            .with_status(201)
            .create();

        server
            .mock("PUT", "/v2/test/test-component/manifests/def5ab3")
            .with_status(200)
            .create();

        let fake = ImplRegistryInterface {};
        let mp = ManifestPlatform {
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
        };
        let layer = Layer {
            digest: String::from(
                "sha256:1b594048db9380f9a8dd2e45e16a2e12d39df51f6f61d9be4c9a2986cbc2828b",
            ),
            media_type: "vnd/object".to_string(),
            size: 112 as i64,
        };
        let layers = vec![layer.clone()];
        let manifest = Manifest {
            schema_version: Some(123 as i64),
            media_type: Some("vnd/test".to_string()),
            platform: Some(mp),
            digest: Some(String::from(
                "sha256:1b594048db9380f9a8dd2e45e16a2e12d39df51f6f61d9be4c9a2986cbc2828b",
            )),
            size: Some(112 as i64),
            config: Some(layer),
            layers: Some(layers),
        };

        let log = &Logging {
            log_level: Level::INFO,
        };

        // test with wrong url
        let res = aw!(fake.push_image(
            log,
            String::from("./test-artifacts"),
            String::from("test-component"),
            String::from(url.clone().replace("http://", "docker://") + "/none"),
            String::from("token"),
            manifest.clone(),
        ));

        assert!(res.is_err());

        // test with correct url
        let res = aw!(fake.push_image(
            log,
            String::from("./test-artifacts"),
            String::from("test-component"),
            String::from(url.clone().replace("http://", "docker://") + "/test"),
            String::from("token"),
            manifest.clone(),
        ));

        assert!(res.is_ok());
    }

    #[test]
    fn get_blobs_file_pass() {
        let res = get_blobs_file(
            String::from("test-artifacts/index-manifest/v1/blobs-store"),
            "1234567890",
        );
        assert_eq!(
            res,
            String::from("test-artifacts/index-manifest/v1/blobs-store/12/1234567890")
        );
    }

    #[test]
    fn get_blobs_dir_pass() {
        let res = get_blobs_dir(
            String::from("test-artifacts/index-manifest/v1/blobs-store/"),
            "1234567890",
        );
        assert_eq!(
            res,
            String::from("test-artifacts/index-manifest/v1/blobs-store/12/")
        );
    }

    #[test]
    fn get_blobs_url_by_string_pass() {
        let res = get_blobs_url_by_string(String::from(
            "test.registry.io/test/some-operator@sha256:1234567890",
        ));
        assert_eq!(
            res,
            String::from("https://test.registry.io/v2/test/some-operator/blobs/")
        );
    }

    #[test]
    fn get_blobs_url_pass() {
        let ir = ImageReference {
            registry: String::from("test.registry.io"),
            namespace: String::from("test"),
            name: String::from("some-operator"),
            version: String::from("v1.0.0"),
        };
        let res = get_blobs_url(ir);
        assert_eq!(
            res,
            String::from("https://test.registry.io/v2/test/some-operator/blobs/")
        );
    }

    #[test]
    fn get_destination_registry_https_blobs_pass() {
        let res = get_destination_registry(
            "docker://127.0.0.1:5000/test".to_string(),
            "test-component".to_string(),
            "https_blobs_uploads".to_string(),
        );
        assert_eq!(
            res,
            String::from("https://127.0.0.1:5000/v2/test/test-component/blobs/uploads/")
        );
    }

    #[test]
    fn get_destination_registry_http_blobs_pass() {
        let res = get_destination_registry(
            "docker://127.0.0.1:5000/test".to_string(),
            "test-component".to_string(),
            "http_blobs_uploads".to_string(),
        );
        assert_eq!(
            res,
            String::from("http://127.0.0.1:5000/v2/test/test-component/blobs/uploads/")
        );
    }

    #[test]
    fn get_destination_registry_http_manifest_pass() {
        let res = get_destination_registry(
            "docker://127.0.0.1:5000/test".to_string(),
            "test-component".to_string(),
            "http_manifest".to_string(),
        );
        assert_eq!(
            res,
            String::from("http://127.0.0.1:5000/v2/test/test-component/manifests/")
        );
    }

    #[test]
    fn get_destination_registry_http_blob_digest_pass() {
        let res = get_destination_registry(
            "docker://127.0.0.1:5000/test".to_string(),
            "test-component".to_string(),
            "http_blobs_digest".to_string(),
        );
        assert_eq!(
            res,
            String::from("http://127.0.0.1:5000/v2/test/test-component/blobs/")
        );
    }

    #[test]
    fn get_destination_registry_http_none_pass() {
        let res = get_destination_registry(
            "docker://127.0.0.1:5000/test".to_string(),
            "test-component".to_string(),
            "http_none".to_string(),
        );
        assert_eq!(
            res,
            String::from("http://127.0.0.1:5000/v2/test/test-component/blobs/uploads/")
        );
    }
    */

    #[test]
    fn err_pass() {
        let err = MirrorError::new(&format!("testing error {}", "123456".to_string()));
        assert_eq!(err.to_string(), "testing error 123456");
    }
}
