package docker.security

# Rule to prevent running as root
violation[msg] {
        input.config.User == "root"
        msg := "Containers must not run as root user"
}

# Rule to enforce approved base images
violation[msg] {
        not approved_base_images[input.config.BaseImage]
        msg := sprintf("Unapproved base image used: %s", [input.config.BaseImage])
}

# Rule to prevent privileged mode
violation[msg] {
        input.config.HostConfig.Privileged == true
        msg := "Privileged mode is not allowed"
}

# Rule to enforce read-only root filesystem
violation[msg] {
        input.config.HostConfig.ReadonlyRootfs == false
        msg := "Root filesystem must be read-only"
}

# Rule to check for security headers
violation[msg] {
        not input.security_headers["Content-Security-Policy"]
        msg := "Missing Content-Security-Policy header"
}

violation[msg] {
        not input.security_headers["X-Frame-Options"]
        msg := "Missing X-Frame-Options header"
}

# Rule to enforce logging
violation[msg] {
        input.config.LogConfig.Type == "none"
        msg := "Logging must be enabled"
}