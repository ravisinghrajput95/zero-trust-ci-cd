package docker.security

# Approved base images
approved_base_images = {"python:3.11-slim", "debian:stable-slim"}

# Rule for security violations
deny_violation[msg] {
        input.config.User == "root"
        msg := "Containers must not run as root user"
}

deny_violation[msg] {
        not approved_base_images[input.config.BaseImage]
        msg := sprintf("Unapproved base image used: %s", [input.config.BaseImage])
}

deny_violation[msg] {
        input.config.HostConfig.Privileged == true
        msg := "Privileged mode is not allowed"
}

deny_violation[msg] {
        input.config.HostConfig.ReadonlyRootfs == false
        msg := "Root filesystem must be read-only"
}

# Ensure security headers exist
deny_violation[msg] {
        not input.security_headers["Content-Security-Policy"]
        msg := "Missing Content-Security-Policy header"
}

deny_violation[msg] {
        not input.security_headers["X-Frame-Options"]
        msg := "Missing X-Frame-Options header"
}

# Deny if logging is disabled
deny_violation[msg] {
        input.config.LogConfig.Type == "none"
        msg := "Logging must be enabled"
}