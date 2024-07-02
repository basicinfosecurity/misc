# Get-MavenData
A script for searching and gathering artifact data including dependencies data from maven central. The data is then saved to csv.
## Usage
```
# Get all artifacts belonging to group "org.springframework"
Get-MavenData -GroupId org.springframework
[*] Retrieving artifacts.
        [+] Getting 1 out of 58 pages.
        [+] Getting 2 out of 58 pages.
        [+] Getting 3 out of 58 pages.
        ...
        [+] Getting 57 out of 58 pages.
        [+] Getting 58 out of 58 pages.
# Get a specific artifact and its dependencies
Get-MavenData -ArtifactId jackson-databind -Version 2.17.0 -GetDependencies
[*] Retrieving artifacts.
        [+] Getting 1 out of 1 pages.
[*] Retrieving dependencies
[*] com.fasterxml.jackson.core:jackson-databind:2.17.0
        [+] Getting 1 out of 1 pages.
```
## Note
There is rate limiting in effect. If the rate limit is reached, an error ```HTTP 429``` is sent back followed by a back off period (around 5 minutes, this amount was not measured).
## References
- https://central.sonatype.org/search/rest-api-guide/
## Changelog
### 2024-03-24
Initial release.
### 2024-07-02
Added GetDependents parameter, fetches dependents data.
