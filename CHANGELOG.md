# Changelog

All notable changes to this project will be documented in this file.

## Release 1.0.2

**Features**

**Bugfixes**
- pw_hash with bcrypt-a seemed to be inconsistent 1 out of ~1000 times resulting in a different hashed password. Hashing functions removed, just provide the module with a pre-hased password as input.

**Known Issues**
