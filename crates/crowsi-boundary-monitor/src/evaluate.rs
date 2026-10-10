use crate::model::{
    BoundaryInputV1, BoundarySnapshotV1, BoundarySummaryV1, EvaluatedEnvironmentV1, SNAPSHOT_SCHEMA,
};

#[must_use]
pub fn evaluate(input: BoundaryInputV1) -> BoundarySnapshotV1 {
    let environments = input
        .environments
        .into_iter()
        .map(|item| {
            let isolation_verified = item.isolation_mode == item.expected_isolation_mode;
            let mut findings = Vec::new();
            if !isolation_verified {
                findings.push("isolation-mode-mismatch".to_owned());
            }
            if item.status != "observed" {
                findings.push("provider-not-connected".to_owned());
            }
            if item.management_endpoint_exposed {
                findings.push("management-endpoint-exposed".to_owned());
            }
            if item.public_ingress {
                findings.push("public-ingress-declared".to_owned());
            }
            let status = if item.status != "observed" {
                "unknown"
            } else if isolation_verified && !item.management_endpoint_exposed {
                "healthy"
            } else {
                "attention"
            };
            EvaluatedEnvironmentV1 {
                id: item.id,
                label: item.label,
                provider: item.provider,
                source: item.source,
                status: status.to_owned(),
                isolation_mode: item.isolation_mode,
                isolation_verified,
                project_count: item.project_count,
                network_count: item.network_count,
                instance_count: item.instance_count,
                public_ingress: item.public_ingress,
                finding_codes: findings,
            }
        })
        .collect::<Vec<_>>();
    let summary = BoundarySummaryV1 {
        environment_count: environments.len(),
        healthy_count: count(&environments, "healthy"),
        attention_count: count(&environments, "attention"),
        unknown_count: count(&environments, "unknown"),
    };
    let overall_status = if summary.attention_count > 0 {
        "attention"
    } else if summary.unknown_count > 0 {
        "unknown"
    } else {
        "healthy"
    };
    BoundarySnapshotV1 {
        schema: SNAPSHOT_SCHEMA.to_owned(),
        generated_at: input.generated_at,
        external_actions: false,
        overall_status: overall_status.to_owned(),
        summary,
        environments,
    }
}

fn count(environments: &[EvaluatedEnvironmentV1], status: &str) -> usize {
    environments
        .iter()
        .filter(|item| item.status == status)
        .count()
}
