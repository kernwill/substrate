# KSI evaluation modules

One Rego module per Key Security Indicator family, each with its own tests.

Families (CR26):
change-management, cloud-native-architecture, cybersecurity-education,
identity-and-access-management, incident-response, monitoring-logging-and-auditing,
policy-and-inventory, recovery-planning, service-configuration, supply-chain-risk

Rules here consume the IR, never raw frontend output.

Every rule must be able to return `undetermined` with a reason. A rule that can
only return pass or fail is wrong: absence of evidence is not evidence of
compliance, and collapsing undetermined into either state is the single most
dangerous bug this project can ship.

Intended for open source release (Apache 2.0).
