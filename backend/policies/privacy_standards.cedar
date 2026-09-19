// Paradox — Privacy Standards Policies (Cedar)
// Based on GDPR, CCPA, DPDP Act (India) principles

// Excessive trackers violate data minimization
forbid(principal, action == Action::"pass", resource == Resource::"privacy_scan")
when { resource.tracker_count > 5 };

// Advertising trackers require consent
forbid(principal, action == Action::"pass", resource == Resource::"cookie_check")
when { resource.category == "advertising" && resource.has_consent == false };

// Session recording must be disclosed
forbid(principal, action == Action::"pass", resource == Resource::"tracker_check")
when { resource.category == "session_recording" };

// Privacy policy is legally required
forbid(principal, action == Action::"pass", resource == Resource::"privacy_policy")
when { resource.exists == false };

// High-risk data sharing without consent
forbid(principal, action == Action::"pass", resource == Resource::"data_sharing")
when { resource.risk == "high" && resource.consent_obtained == false };
