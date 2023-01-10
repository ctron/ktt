use anyhow::bail;
use auditable_info::{Error, Limits};
use auditable_serde::{DependencyKind, Package, Source, VersionInfo};
use cyclonedx_bom::models::component::{Classification, Scope};
use cyclonedx_bom::models::tool::{Tool, Tools};
use cyclonedx_bom::prelude::{
    Bom, Component, Components, DateTime, Metadata, NormalizedString, Purl, UrnUuid,
};
use std::io::{stdin, stdout, Write};
use std::path::Path;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct Options {
    pub input: Option<String>,
}

pub(crate) fn run(opts: Options) -> anyhow::Result<()> {
    log::info!(
        "Generating SBOM for {}",
        opts.input.as_deref().unwrap_or("<stdin>")
    );

    let limits = Limits::default();

    let info = match opts.input {
        Some(file) => auditable_info::audit_info_from_file(Path::new(&file), limits),
        None => auditable_info::audit_info_from_reader(&mut stdin().lock(), limits),
    }
    .map(Some)
    .or_else(|err| match err {
        Error::NoAuditData => Ok(None),
        err => Err(err),
    })?;

    match info {
        Some(info) => render_sbom(&info, &mut stdout().lock())?,
        None => {
            // TODO: we could let the user decide, fail, or just have no dependency info
            bail!("No dependency information found. Ensure the binary was built using 'cargo auditable build'");
        }
    }

    Ok(())
}

fn render_sbom<W: Write>(info: &VersionInfo, writer: &mut W) -> anyhow::Result<()> {
    log::debug!("Raw version info: {info:?}");

    let root = find_root(info);

    let root = match root {
        Some(root) => root,
        None => bail!("Unable to find root package in metadata"),
    };

    let bom = Bom {
        version: 1,
        serial_number: Some(UrnUuid::generate()),
        metadata: Some(Metadata {
            timestamp: Some(DateTime::now()?),
            tools: Some(to_tools(info)),
            authors: None,
            component: Some(to_component(root, Classification::Application)?),
            manufacture: None,
            supplier: None,
            licenses: None,
            properties: None,
        }),
        components: Some(to_components(info)?),
        services: None,
        external_references: None,
        dependencies: None,
        compositions: None,
        properties: None,
    };

    bom.output_as_json_v1_3(writer)?;

    Ok(())
}

fn find_root(info: &VersionInfo) -> Option<&Package> {
    info.packages.iter().find(|p| p.root)
}

fn to_tools(info: &VersionInfo) -> Tools {
    let mut tools: Vec<_> = info
        .packages
        .iter()
        .filter(|p| p.kind == DependencyKind::Build)
        .map(to_tool)
        .collect();

    // add ourselves

    tools.push(Tool {
        vendor: None,
        name: Some(NormalizedString::new(NAME)),
        version: Some(NormalizedString::new(VERSION)),
        hashes: None,
    });

    // return

    Tools(tools)
}

fn to_tool(package: &Package) -> Tool {
    // FIXME: consider expanding dependencies of tools too
    Tool {
        vendor: None,
        name: Some(NormalizedString::new(&package.name)),
        version: Some(NormalizedString::new(&package.version.to_string())),
        hashes: None,
    }
}

fn to_components(info: &VersionInfo) -> anyhow::Result<Components> {
    Ok(Components(
        info.packages
            .iter()
            .filter(|p| !p.root && p.kind == DependencyKind::Runtime)
            .map(|p| to_component(p, Classification::Library))
            .collect::<Result<_, _>>()?,
    ))
}

fn to_component(package: &Package, component_type: Classification) -> anyhow::Result<Component> {
    Ok(Component {
        component_type,
        mime_type: None,
        bom_ref: None,
        supplier: None,
        author: None,
        publisher: None,
        group: None,
        name: NormalizedString::new(&package.name),
        version: NormalizedString::new(&package.version.to_string()),
        description: None,
        scope: Some(Scope::Required),
        hashes: None,
        licenses: None,
        copyright: None,
        cpe: None,
        purl: to_purl(&package)?,
        swid: None,
        modified: None,
        pedigree: None,
        external_references: None,
        properties: None,
        components: None,
        evidence: None,
    })
}

fn to_purl(package: &Package) -> anyhow::Result<Option<Purl>> {
    Ok(match &package.source {
        Source::CratesIo => Some(Purl::new(
            "cargo",
            &package.name,
            &package.version.to_string(),
        )?),
        _ => None,
    })
}
