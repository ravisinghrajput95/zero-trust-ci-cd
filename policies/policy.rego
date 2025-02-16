package docker.security

# Define the list of approved base images
approved_base_images = [
    "python:3.11-slim"
]

# Main deny rule for unauthorized base images
deny[msg] {
    input.config.BaseImage
    image:= input.config.BaseImage
    not image_in_approved_base_images(image)
    msg:= sprintf("Base image '%s' is not approved", [image])
}

# Function to check if an image is in the approved list
image_in_approved_base_images(image) {
    approved_base_images[_] == image
}

# Rule to prevent running as root
deny[msg] {
    input.config.User == "root"
    msg:= "Containers must not run as root user"
}

# Rule to prevent privileged mode
deny[msg] {
    input.config.HostConfig.Privileged == true
    msg:= "Privileged mode is not allowed"
}

# Rule to enforce read-only root filesystem
deny[msg] {
    input.config.HostConfig.ReadonlyRootfs == false
    msg:= "Root filesystem must be read-only"
}

# Rule to check for Content-Security-Policy header
deny[msg] {
    not input.security_headers["Content-Security-Policy"]
    msg:= "Missing Content-Security-Policy header"
}

deny[msg] {
    input.security_headers["Content-Security-Policy"]
    not contains(input.security_headers["Content-Security-Policy"], "default-src 'self'")
    msg:= "Content-Security-Policy must include 'default-src 'self'"
}

deny[msg] {
    input.security_headers["Content-Security-Policy"]
    not contains(input.security_headers["Content-Security-Policy"], "script-src 'self'")
    msg:= "Content-Security-Policy must include 'script-src 'self'"
}

# Rule to check for X-Frame-Options header
deny[msg] {
    not input.security_headers["X-Frame-Options"]
    msg:= "Missing X-Frame-Options header"
}

deny[msg] {
    input.security_headers["X-Frame-Options"]
    not contains(input.security_headers["X-Frame-Options"], "DENY")  # Or "SAMEORIGIN"
    msg:= "X-Frame-Options must be DENY (or SAMEORIGIN)"
}

# Rule to enforce logging configuration
deny[msg] {
    input.config.LogConfig.Type == "none"
    msg:= "Logging must be enabled"
}

# Input Validation (Add as needed - VERY IMPORTANT):

deny[msg] {
    not input.config
    msg:= "Missing 'config' section in input"
}

deny[msg] {
    not input.config.BaseImage
    msg:= "Missing 'config.BaseImage' in input"
}

deny[msg] {
    not input.config.HostConfig
    msg:= "Missing 'config.HostConfig' in input"
}

deny[msg] {
    input.config.HostConfig
    not input.config.HostConfig.Privileged
    msg:= "Missing 'config.HostConfig.Privileged' in input"
}

deny[msg] {
    not input.config.HostConfig.LogConfig
    msg:= "Missing 'config.HostConfig.LogConfig' in input"
}

deny[msg] {
    not input.config.LogConfig.Type
    msg:= "Missing 'config.LogConfig.Type' in input"
}

deny[msg] {
  not input.security_headers
  msg:= "Missing 'security_headers' in input"
}

deny[msg] {
  not input.security_headers["Content-Security-Policy"]
  msg:= "Missing 'security_headers.Content-Security-Policy' in input"
}