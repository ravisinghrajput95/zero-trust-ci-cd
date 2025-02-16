package docker.security

# Define the list of approved base images
approved_base_images = [
    "python:3.11-slim"
]

# Main deny rule for unauthorized base images
deny[msg] {
    input.config.BaseImage
    not contains(approved_base_images, input.config.BaseImage)
    msg := sprintf("Base image '%s' is not approved", [input.config.BaseImage])
}

# Rule to prevent running as root
deny[msg] {
    input.config.User == "root"
    msg := "Containers must not run as root user"
}

# Rule to prevent privileged mode
deny[msg] {
    input.config.HostConfig.Privileged == true
    msg := "Privileged mode is not allowed"
}

# Rule to enforce read-only root filesystem
deny[msg] {
    input.config.HostConfig.ReadonlyRootfs == false
    msg := "Root filesystem must be read-only"
}

# Rule to check for Content-Security-Policy header
deny[msg] {
    not input.security_headers["Content-Security-Policy"]
    msg := "Missing Content-Security-Policy header"
}

# Rule to check for X-Frame-Options header
deny[msg] {
    not input.security_headers["X-Frame-Options"]
    msg := "Missing X-Frame-Options header"
}

# Rule to enforce logging configuration
deny[msg] {
    input.config.LogConfig.Type == "none"
    msg := "Logging must be enabled"
}