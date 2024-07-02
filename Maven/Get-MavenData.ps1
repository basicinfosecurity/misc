<#
    .Description
    Get-MavenData is a script for searching and gathering artifact data including dependencies data from maven central. The data is then saved to csv.
    .Parameter ArtifactId
    The name of the artifact (e.g. jackson-databind).
    .Parameter GroupId
    The name of the group (e.g. com.fasterxml.jackson.core).
    .Parameter Version
    The version number (e.g. 2.15.0-rc1)
    .Parameter GetDependencies
    If this paramter is included, the script will retrieve dependencies of each artifact.
    .Parameter GetDependents
    If this paramter is included, the script will retrieve dependents of each artifact.
    .Parameter Suppress
    If this paramter is included, the script will hide console output.
    .Parameter Proxy
    Directs the script to use a proxy.
    .SYNOPSIS
    Get-MavenData is a script for retrieving artifact data from maven.
    .EXAMPLE
    Get-MavenData -ArtifactId jackson-databind -GroupId com.fasterxml.jackson.core
    .EXAMPLE
    Get-MavenData -ArtifactId jackson-databind -Version 2.17.0 -GetDependencies
    .EXAMPLE
    Get-MavenData -GroupId org.springframework -Suppress
    .EXAMPLE
    Get-MavenData -GetDependents -ArtifactId snakeyaml -Version 1.17
#>
function Get-MavenData{
    param (
        [Parameter()]
        [string]$ArtifactId,
        [string]$GroupId,
        [string]$Version,
        [string]$Proxy = "",
        [switch]$GetDependencies = $false,
        [switch]$GetDependents = $false,
        [switch]$Suppress = $false
    )
    begin{
        $page = 0
        $pages = 1
        $params = foreach($param in @("g:$GroupId", "a:$ArtifactId", "v:$Version")){
            if($param.Length -gt 2){
                $param
            }
        }
        $offset = 100
        $query = $params -join " AND "
        $Body = @{
            "q" = $query
            "wt" = "json"
            "rows" = $offset
            "core" = "gav"
            "start" = 0
        }
        $searchEndpoint = "https://search.maven.org/solrsearch/select"
        $dependenciesEndpoint = "https://central.sonatype.com/api/internal/browse/dependencies"
        $dependentsEndpoint = "https://central.sonatype.com/api/internal/browse/dependents"
        $endpoint = $null
        $msg = "dependents"
        $file_prefix = "maven_"
        
        if($Suppress){
            function Write-Host {}
        }
    }
    process{
        try {
            Write-Host "[*] Retrieving artifacts."
            $searchData = [System.Collections.ArrayList]::new()
            while ($page -lt $pages) {
                $arguments = @{
                    UseBasicParsing = $true
                    Uri = $searchEndpoint
                    Body = $Body
                }
                if($Proxy){ $arguments["Proxy"] = $Proxy}
                $request = Invoke-RestMethod @arguments
                $total = $request.response.numFound
                if($total -eq 0) { throw "No items found." }
                $pages = [System.Math]::Floor([decimal]($total / $offset)) + 1
                $page += 1
                Write-Host "`t[+] Getting $page out of $pages pages."
                $Body["start"] = $page * $offset
                foreach($item in $request.response.docs){
                    $tmp = [PSCustomObject]@{
                        ArtifactId = $item.id
                        GroupId = $item.g
                        Name = $item.a
                        Version = $item.v
                    }
                    $null = $searchData.Add($tmp)
                }
            }
            
            if($GetDependencies){
                $endpoint = $dependenciesEndpoint
                $msg = "dependencies"
                $file_prefix = "$file_prefix$msg"
            }
            elseif($GetDependents){
                $endpoint = $dependentsEndpoint
                $file_prefix = "$file_prefix$msg"
            }
            
            if($endpoint){
                Write-Host "[*] Retrieving $msg"
                # $dependencies = [System.Collections.ArrayList]::new()
                $records = [System.Collections.ArrayList]::new()
                foreach($artifact in $searchData){
                    $page = 0
                    $pages = 1
                    $purl = "pkg:maven/$($artifact.GroupId)/$($artifact.Name)@$($artifact.Version)"
                    $offset = 20 # This seems to be the maximum, anything else will return HTTP 400
                    $json = @{
                        "page" = $page
                        "purl" = $purl
                        "searchTerm" = $SearchTerm
                        "size" = $offset
                    }
                    $contentType = "application/json"
                    $headers = @{
                        "Content-Type" = $contentType
                        "Accept" = $contentType
                    }
                    Write-Host "[*] $($artifact.ArtifactId)"
                    while($page -lt $pages){
                        $arguments = @{
                            UseBasicParsing = $true
                            Uri = $endpoint
                            Body = ($json | ConvertTo-Json)
                            Method = "Post"
                            Headers = $headers
                        }
                        if($Proxy){ $arguments["Proxy"] = $Proxy}
                        $response = Invoke-RestMethod @arguments
                        if($response.totalResultCount -eq 0) {
                            $null = $records.Add($item)
                            break
                        }
                        $pages = $response.pageCount
                        $page += 1
                        Write-Host "`t[+] Getting $page out of $pages pages."
                        $json["page"] = $page
                        foreach($item in $response.components){
                            $item.licenses = $item.licenses -join "|| "
                            $null = $records.Add($item)
                        }
                    }
                }
            }
        }
        catch {
            if($Suppress){ Remove-Item -Path function:Write-Host }
            Write-Host "[-] $($_.Exception.Message)" -ForegroundColor "Red"
            Write-Host "`t$($PSItem.ScriptStackTrace)" -ForegroundColor "Red"
        }
        finally {
            $timestamp = $(Get-Date -Format ddMMyyyy_hhmmss)
            if($searchData.Count -gt 0){
                $csv = "maven_artifacts-$timestamp.csv"
                $searchData | Export-Csv -NoTypeInformation $csv
            }
            if($records.Count -gt 0){
                $csv = "$file_prefix-$timestamp.csv"
                $records | Export-Csv -NoTypeInformation $csv
            }
        }
    }
}