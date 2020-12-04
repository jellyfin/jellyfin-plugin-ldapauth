<h1 align="center">Jellyfin LDAP-Auth Plugin</h1>
<h3 align="center">Part of the <a href="https://jellyfin.media">Jellyfin Project</a></h3>

<p align="center">

<img alt="Logo Banner" src="https://raw.githubusercontent.com/jellyfin/jellyfin-ux/master/branding/SVG/banner-logo-solid.svg?sanitize=true"/>
<br/>
<br/>
<a href="https://github.com/jellyfin/jellyfin-plugin-ldapauth/actions?query=workflow%3A%22Test+Build+Plugin%22">
<img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/jellyfin/jellyfin-plugin-ldapauth/Test%20Build%20Plugin.svg">
</a>
<a href="https://github.com/jellyfin/jellyfin-plugin-ldapauth">
<img alt="MIT License" src="https://img.shields.io/github/license/jellyfin/jellyfin-plugin-ldapauth.svg"/>
</a>
<a href="https://github.com/jellyfin/jellyfin-plugin-ldapauth/releases">
<img alt="Current Release" src="https://img.shields.io/github/release/jellyfin/jellyfin-plugin-ldapauth.svg"/>
</a>
</p>

## Description

LDAP authentication for Jellyfin Media Server. JelLDAP, if you will.

Authenticate your Jellyfin users against an LDAP database, and optionally create users who do not yet exist automatically.

Allows the administrator to customize most aspects of the LDAP authentication process, including customizable search attributes, username attribute, and a search filter for administrative users (set on user creation). The user, via the "Manual Login" process, can enter any valid attribute value, which will be mapped back to the specified username attribute automatically as well.

## Installation

[See the official documentation for install instructions](https://jellyfin.org/docs/general/server/plugins/index.html#installing).

## Contributing

We welcome all contributions and pull requests!
If you have a larger feature in mind please open an issue so we can discuss the implementation before you start.

## Build Process

### Dependencies

- .NET Core 5.0

### Getting Started
1. Clone or download this repository

2. Ensure you have .NET Core SDK setup and installed

3. Build plugin with following command.

   ```sh
   dotnet publish --configuration Release --output bin
   ```

4. Place the resulting file in the `plugins` folder under the program data directory or inside the portable install directory
