package docker.security

# Enforce only approved base images
approved_base_images := {
    "python:3.11-slim",
    "debian:stable-slim"
}

# Ensure non-root user is used in the container
deny[msg] {
    input.config.User == "root"
    msg := "Containers must not run as root user"
}

# Ensure the base image is from the approved list
deny[msg] {
    not input.config.BaseImage in approved_base_images
    msg := sprintf("Unapproved base image used: %s", [input.config.BaseImage])
}

# Restrict privileged mode
deny[msg] {
    input.config.HostConfig.Privileged == true
    msg := "Privileged mode is not allowed"
}

# Ensure read-only root filesystem
deny[msg] {
    input.config.HostConfig.ReadonlyRootfs == false
    msg := "Root filesystem must be read-only"
}

# Restrict dangerous capabilities
dangerous_capabilities := {"SYS_ADMIN", "NET_ADMIN", "DAC_OVERRIDE"}
deny[msg] {
    some cap in input.config.HostConfig.CapAdd
    cap in dangerous_capabilities
    msg := sprintf("Container should not have dangerous capability: %s", [cap])
}

# Ensure necessary security headers
deny[msg] {
    not input.security_headers["Content-Security-Policy"]
    msg := "Missing Content-Security-Policy header"
}

deny[msg] {
    not input.security_headers["X-Frame-Options"]
    msg := "Missing X-Frame-Options header"
}

# Ensure logging is enabled
deny[msg] {
    input.config.LogConfig.Type == "none"
    msg := "Logging must be enabled"
}

