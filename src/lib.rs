use async_trait::async_trait;
use core::fmt;
use custom_logger::*;
use futures::{stream, StreamExt};
use hex::encode;
use reqwest::{Client, StatusCode};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestList {
    #[serde(rename = "manifests")]
    pub manifests: Vec<Manifest>,

    #[serde(rename = "mediaType")]
    pub media_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsLayer {
    pub blob_sum: String,
    pub original_ref: Option<String>,
    pub size: Option<i64>,
}

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

// ImageReference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub namespace: String,
    pub name: String,
    pub version: String,
}

// DestinationRegistry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationRegistry {
    pub protocol: String,
    pub registry: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorError {
    details: String,
}

impl MirrorError {
    pub fn new(msg: &str) -> MirrorError {
        MirrorError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

#[derive(Debug, Clone)]
pub struct ImplRegistryInterface {}

#[async_trait]
pub trait RegistryInterface {
    // used to interact with container registry (manifest calls)
    // this seems strange to expose the get manifest and get blobs
    // rather than just get images (as in push_image)
    // the separation is to allow for more flexibility in just querying (getting)
    // manifests and then based on the response, we can decide to download blobs
    async fn get_manifest(
        &self,
        url: String,
        token: String,
    ) -> Result<String, Box<dyn std::error::Error>>;

    // used to interact with container registry (retrieve blobs)
    async fn get_blobs(
        &self,
        log: &Logging,
        dir: String,
        url: String,
        token: String,
        layers: Vec<FsLayer>,
    ) -> Result<String, Box<dyn std::error::Error>>;

    // used to interact with container registry (push blobs)
    async fn push_image(
        &self,
        log: &Logging,
        dir: String,
        sub_component: String,
        url: String,
        token: String,
        manifest: Manifest,
    ) -> Result<String, MirrorError>;
}

#[async_trait]
impl RegistryInterface for ImplRegistryInterface {
    async fn get_manifest(
        &self,
        url: String,
        token: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = Client::new();
        // check without token
        if token.len() == 0 {
            let body = client
                .get(url)
                .header("Accept", "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json")
                .header("Content-Type", "application/json")
                .send()
                .await?
                .text()
                .await?;

            return Ok(body);
        }

        let mut header_bearer: String = "Bearer ".to_owned();
        header_bearer.push_str(&token);
        let body = client
            .get(url)
            .header("Accept", "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json")
            .header("Content-Type", "application/json")
            .header("Authorization", header_bearer)
            .send()
            .await?
            .text()
            .await?;

        Ok(body)
    }
    // get each blob referred to by the vector in parallel
    // set by the PARALLEL_REQUESTS value
    async fn get_blobs(
        &self,
        log: &Logging,
        dir: String,
        url: String,
        token: String,
        layers: Vec<FsLayer>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        const PARALLEL_REQUESTS: usize = 16;
        let client = Client::new();

        // remove all duplicates in FsLayer
        let mut images = Vec::new();
        let mut seen = HashSet::new();
        for img in layers.iter() {
            // truncate sha256:
            let truncated_image = img.blob_sum.split(":").nth(1).unwrap();
            let inner_blobs_file = get_blobs_file(dir.clone(), &truncated_image);
            let mut exists = Path::new(&inner_blobs_file).exists();
            if exists {
                let metadata = fs::metadata(&inner_blobs_file).unwrap();
                if img.size.is_some() {
                    if metadata.len() != img.size.unwrap() as u64 {
                        exists = false;
                    }
                } else {
                    exists = false;
                }
            }

            // filter out duplicates
            if !seen.contains(&truncated_image) && !exists {
                seen.insert(truncated_image);
                if url == "" {
                    let img_orig = img.original_ref.clone().unwrap();
                    let img_ref = get_blobs_url_by_string(img_orig);
                    let layer = FsLayer {
                        blob_sum: img.blob_sum.clone(),
                        original_ref: Some(img_ref),
                        size: img.size,
                    };
                    images.push(layer);
                } else {
                    let layer = FsLayer {
                        blob_sum: img.blob_sum.clone(),
                        original_ref: Some(url.clone()),
                        size: img.size,
                    };
                    images.push(layer);
                }
            }
        }
        log.debug(&format!("blobs to download {}", images.len()));
        log.trace(&format!("fslayers vector {:#?}", images));
        let mut header_bearer: String = "Bearer ".to_owned();
        header_bearer.push_str(&token);

        if images.len() > 0 {
            log.debug("downloading blobs...");
        }

        let fetches = stream::iter(images.into_iter().map(|blob| {
            let client = client.clone();
            let url = blob.original_ref.unwrap().clone();
            let header_bearer = header_bearer.clone();
            let wrk_dir = dir.clone();

            async move {
                match client
                    .get(url.clone() + &blob.blob_sum)
                    .header("Authorization", header_bearer)
                    .send()
                    .await
                {
                    Ok(resp) => match resp.bytes().await {
                        Ok(bytes) => {
                            let blob_digest = blob.blob_sum.split(":").nth(1).unwrap();
                            let blob_dir = get_blobs_dir(wrk_dir.clone(), blob_digest);
                            fs::create_dir_all(blob_dir.clone())
                                .expect("unable to create direcory");
                            fs::write(blob_dir + &blob_digest, bytes.clone())
                                .expect("unable to write blob");
                            let msg = format!("writing blob {}", blob_digest);
                            log.info(&msg);
                        }
                        Err(_) => {
                            let msg = format!("writing blob {}", url.clone());
                            log.error(&msg);
                            //return Err(e);
                        }
                    },
                    Err(e) => {
                        // TODO: update signature to Box<dyn MirrorError>
                        // and return the error
                        //let msg = format!("downloading blob {}", &url);
                        //log.error(&msg);
                        let err = MirrorError::new(&e.to_string());
                        log.error(&err.to_string());
                    }
                }
            }
        }))
        .buffer_unordered(PARALLEL_REQUESTS)
        .collect::<Vec<()>>();
        fetches.await;
        Ok(String::from("ok"))
    }
    // push each image (blobs and manifest) referred to by the Manifest
    async fn push_image(
        &self,
        log: &Logging,
        dir: String,
        sub_component: String,
        url: String,
        token: String,
        manifest: Manifest,
    ) -> Result<String, MirrorError> {
        let client = Client::new();
        let client = client.clone();

        // we iterate through all the layers
        for blob in manifest.clone().layers.unwrap().iter() {
            let process_res = process_blob(
                log,
                dir.clone(),
                &blob,
                url.clone(),
                sub_component.clone(),
                token.clone(),
            )
            .await?;
            log.debug(&format!(
                "processed blob status {:#?} : {:#?}",
                process_res, blob.digest
            ));
        }

        // mirror the config blob
        let blob = manifest.clone().config.unwrap();
        let _process_res = process_blob(
            log,
            dir.clone(),
            &blob,
            url.clone(),
            sub_component.clone(),
            token.clone(),
        )
        .await?;

        // finally push the manifest
        let serialized_manifest = serde_json::to_string(&manifest.clone()).unwrap();
        log.trace(&format!("manifest json {:#?}", serialized_manifest.clone()));
        let put_url = get_destination_registry(
            url.clone(),
            sub_component.clone(),
            String::from("http_manifest"),
        );

        let mut hasher = Sha256::new();
        hasher.update(serialized_manifest.clone());
        let hash_bytes = hasher.finalize();
        let str_digest = encode(hash_bytes);
        let res_put = client
            .put(put_url.clone() + &str_digest.clone()[0..7])
            .body(serialized_manifest.clone())
            .header(
                "Content-Type",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .header("Content-Length", serialized_manifest.len())
            .send()
            .await;

        let result = res_put.unwrap();
        log.info(&format!("processed image {}", str_digest));
        log.debug(&format!(
            "result for manifest {:#?} {} {}",
            result.status(),
            sub_component,
            put_url.clone() + &str_digest.clone()[0..7]
        ));

        if result.status() != StatusCode::CREATED && result.status() != StatusCode::OK {
            let err = MirrorError::new(&format!(
                "upload manifest failed with status {:#?}",
                result.status()
            ));
            Err(err)
        } else {
            Ok(String::from("ok"))
        }
    }
}

// Refer to https://distribution.github.io/distribution/spec/api/
// for the full flow on image (container) push
// 1. First step is to post a blob
//    POST /v2/<name>/blobs/uploads/
//    If the POST request is successful, a 202 Accepted response will be returned
//    with Location and UUID
// 2. Check if the blob exists
//    HEAD /v2/<name>/blobs/<digest>
//    If the layer with the digest specified in digest is available, a 200 OK response will be received,
//    with no actual body content (this is according to http specification).
// 3. If it does not exist do a put
//    PUT /v2/<name>/blobs/uploads/<uuid>?digest=<digest>
//    continue for each blob in the specifid container
// 4. Finally upload the manifest
//    PUT /v2/<name>/manifests/<reference>
pub async fn process_blob(
    log: &Logging,
    dir: String,
    blob: &Layer,
    url: String,
    sub_component: String,
    token: String,
) -> Result<String, MirrorError> {
    let client = Client::new();
    let client = client.clone();
    let mut header_bearer: String = "Bearer ".to_owned();
    header_bearer.push_str(&token);

    // TODO: add https functionality
    let post_url = get_destination_registry(
        url.clone(),
        sub_component.clone(),
        String::from("http_blobs_uploads"),
    );

    let res = client
        .post(post_url.clone())
        .header("Accept", "*/*")
        .send()
        .await;

    let response = res.unwrap();

    if response.status() != StatusCode::ACCEPTED {
        let err = MirrorError::new(&format!(
            "initial post failed with status {:#?}",
            response.status()
        ));
        return Err(err);
    }

    log.debug(&format!("headers {:#?}", response.headers()));
    let location = response.headers().get("Location").unwrap();
    //let _uuid = response.headers().get("docker-upload-uuid").unwrap();

    let head_url = get_destination_registry(
        url.clone(),
        sub_component.clone(),
        String::from("http_blobs_digest"),
    );

    let digest_no_sha = blob.digest.split(":").nth(1).unwrap().to_string();
    let path = String::from(dir + "/blobs-store/") + &digest_no_sha[0..2] + &"/" + &digest_no_sha;

    let res_head = client
        .head(head_url.clone() + &blob.digest)
        .header("Accept", "*/*")
        .send()
        .await;

    let response = res_head.unwrap();

    // if blob is not found we need to upload it
    if response.status() == StatusCode::NOT_FOUND {
        let mut file = File::open(path.clone()).await.unwrap();
        let mut vec = Vec::new();
        let _buf = file.read_to_end(&mut vec).await.unwrap();
        let url = location.to_str().unwrap().to_string() + &"&digest=" + &blob.digest;
        log.info(&format!(
            "content length  {:#?} {:#?}",
            vec.clone().len(),
            &blob.digest
        ));

        let res_put = client
            .put(url)
            .body(vec.clone())
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", vec.len())
            .send()
            .await;

        let res_final = res_put.unwrap();

        log.debug(&format!("result from put blob {:#?}", res_final.status()));

        if res_final.status() > StatusCode::CREATED {
            let err =
                MirrorError::new(&format!("put blob failed with code {}", res_final.status()));
            return Err(err);
        }
    }
    Ok(String::from("ok"))
}

// parse the manifest json for operator indexes only
pub fn parse_json_manifestlist(data: String) -> Result<ManifestList, Box<dyn std::error::Error>> {
    // Parse the string of data into serde_json::Manifest.
    let root: ManifestList = serde_json::from_str(&data)?;
    Ok(root)
}

// parse the manifest json for operator indexes only
pub fn parse_json_manifest_operator(data: String) -> Result<Manifest, Box<dyn std::error::Error>> {
    // Parse the string of data into serde_json::Manifest.
    let root: Manifest = serde_json::from_str(&data)?;
    Ok(root)
}

// construct the blobs url
pub fn get_blobs_url(image_ref: ImageReference) -> String {
    // return a string in the form of (example below)
    // "https://registry.redhat.io/v2/redhat/certified-operator-index/blobs/";
    let mut url = String::from("https://");
    url.push_str(&image_ref.registry);
    url.push_str(&"/v2/");
    url.push_str(&image_ref.namespace);
    url.push_str("/");
    url.push_str(&image_ref.name);
    url.push_str(&"/");
    url.push_str(&"blobs/");
    url
}

// construct the blobs url by string
pub fn get_blobs_url_by_string(img: String) -> String {
    let mut parts = img.split("/");
    let mut url = String::from("https://");
    url.push_str(&parts.nth(0).unwrap());
    url.push_str(&"/v2/");
    url.push_str(&parts.nth(0).unwrap());
    url.push_str(&"/");
    let i = parts.nth(0).unwrap();
    let mut sha = i.split("@");
    url.push_str(&sha.nth(0).unwrap());
    url.push_str(&"/blobs/");
    url
}
// construct blobs dir
pub fn get_blobs_dir(dir: String, name: &str) -> String {
    // originally working-dir/blobs-store
    let mut file = dir.clone();
    file.push_str(&name[..2]);
    file.push_str(&"/");
    file
}
// construct blobs file
pub fn get_blobs_file(dir: String, name: &str) -> String {
    // originally working-dir/blobs-store
    let mut file = dir.clone();
    file.push_str("/");
    file.push_str(&name[..2]);
    file.push_str(&"/");
    file.push_str(&name);
    file
}

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

        let real = ImplRegistryInterface {};

        let res = aw!(real.get_manifest(url + "/manifests", String::from("token")));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), String::from("{ \"test\": \"hello-world\" }"));
    }

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

    #[test]
    fn err_pass() {
        let err = MirrorError::new(&format!("testing error {}", "123456".to_string()));
        assert_eq!(err.to_string(), "testing error 123456");
    }
}
