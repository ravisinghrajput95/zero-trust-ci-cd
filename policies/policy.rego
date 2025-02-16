package docker.security

# Approved base images
approved_base_images := {
    "python:3.11-slim",
    "debian:stable-slim"
}

# Deny running as root user
deny[msg] {
    input.config.User == "root"
    msg := "Containers must not run as root user"
}

# Deny unapproved base images
deny[msg] {
    not input.config.BaseImage in approved_base_images
    msg := sprintf("Unapproved base image used: %s", [input.config.BaseImage])
}

# Deny privileged mode
deny[msg] {
    input.config.HostConfig.Privileged == true
    msg := "Privileged mode is not allowed"
}

# Deny non-read-only root filesystem
deny[msg] {
    input.config.HostConfig.ReadonlyRootfs == false
    msg := "Root filesystem must be read-only"
}

# Deny dangerous capabilities
dangerous_capabilities := {"SYS_ADMIN", "NET_ADMIN", "DAC_OVERRIDE"}
deny[msg] {
    some cap in input.config.HostConfig.CapAdd
    cap in dangerous_capabilities
    msg := sprintf("Container should not have dangerous capability: %s", [cap])
}

# Ensure security headers exist
deny[msg] {
    not input.security_headers["Content-Security-Policy"]
    msg := "Missing Content-Security-Policy header"
}

deny[msg] {
    not input.security_headers["X-Frame-Options"]
    msg := "Missing X-Frame-Options header"
}

# Deny if logging is disabled
deny[msg] {
    input.config.LogConfig.Type == "none"
    msg := "Logging must be enabled"
}