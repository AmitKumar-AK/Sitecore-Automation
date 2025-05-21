$ErrorActionPreference = "Stop"
$EnvFileName = ".env"  # Default name of the .env file
$bearerToken = ""  # Initialize bearer token variable
# Get the environment variable from the .env file
function GetEnvVariable {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path of the .env file.")]
        [string]$filePath = ".env",  # Default path for the .env file
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the .env name.")]
        [string]$varName  # Name of the environment variable to retrieve
    )

    Write-Host "Inside GetEnvVariable"  # Log entry into the function

    $envFilePath = Resolve-Path "$PSScriptRoot\$filePath"  # Resolve the full path of the .env file

    if (Test-Path $envFilePath) {  # Check if the .env file exists
        if ($varName -ne "" -and $envFilePath -ne "") {  # Ensure parameters are not empty
            Write-Host "Using .env file: $envFilePath" -ForegroundColor Cyan  # Log the file being used
            # Read the contents of the .env file
            $envFileContent = Get-Content -Path $envFilePath  # Load the file content into an array

            # Iterate through each line to find the variable
            foreach ($line in $envFileContent) {
                if ($line -match "^\s*$varName\s*=\s*(.+)\s*$") {  # Check if the line matches the variable name
                    $varValue = $matches[1].Trim()  # Extract the variable value
                    Write-Host "Environment variable '$varName' found with value '$varValue'."  # Log success message
                    return $varValue  # Return the found value
                }
            }

            Write-Host "Environment variable '$varName' not found in the .env file." -ForegroundColor Yellow  # Log if not found
            return $null  # Return null if not found
        } else {
            Write-Host "Invalid parameters" -ForegroundColor Red  # Log error for invalid parameters
            return $null  # Return null for invalid parameters
        }
    } else {
        Write-Error "The .env file does not exist at the specified path: $envFilePath"  # Log error if file doesn't exist
        return $null  # Return null if file doesn't exist
    }
}
function GetWebhookListing {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path of the .env file.")]
        [string]$filePath = ".env"  # Default path for the .env file
    )

    Write-Host "Inside GetWebhookListing"  # Log entry into the function

    $envFilePath = Resolve-Path "$PSScriptRoot\$filePath"  # Resolve the full path of the .env file

    if (Test-Path $envFilePath) {  # Check if the .env file exists
        if ($varName -ne "" -and $envFilePath -ne "") {  # Ensure parameters are not empty
            Write-Host "Using .env file: $envFilePath" -ForegroundColor Cyan  # Log the file being used
            # Read the contents of the .env file
            $sitecoreEdgeApi = GetEnvVariable -filePath $EnvFileName -varName "SITECORE_EDGE_API"
            
            # Write-Host "Local variable bearerToken set with value '$bearerToken'."

            Write-Host "Calling Sitecore Edge API to get webhooks..."
            
            $headers = @{ Authorization = "Bearer $bearerToken" }
            
            try {
                $response = Invoke-WebRequest -Uri $sitecoreEdgeApi -Headers $headers -Method GET -ErrorAction Stop
                $statusCode = $response.StatusCode

                # Print the raw response content
                # Write-Host "Response Content GetWebhookListing:"
                # Write-Host $response.Content                
            } catch {
                Write-Host "Error occurred: $($_.Exception.Message)"
                if ($_.Exception.Response -ne $null) {
                    $statusCode = $_.Exception.Response.StatusCode
                } else {
                    throw "Unexpected error occurred: $($_.Exception.Message)"
                }
            }
            
            # Handle the status code and execute the next step
            switch ($statusCode) {
                200 {
                    Write-Host "Successfully retrieved webhooks:"
                    $response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
                    # Add your next step for success here
                }
                401 {
                    Write-Host "Unauthorized access 401. Please check your bearer token."
                    Write-Host "Response content: $($response.Content)"
                    Write-Warning "JWT verification failed. Requesting new token..."
                    # Add your next step for unauthorized access here
                    $bearerToken=GetAccessToken -filePath $EnvFileName
                    Write-Host "Local variable bearerToken received from GetAccessToken function is '$bearerToken'."  # Log success message
                    GetWebhookListing -filePath $EnvFileName
                }
                default {
                    if ($statusCode -match "Unauthorized") {
                        Write-Host "Unauthorized error detected. Please verify your credentials or token."
                        Write-Warning "JWT verification failed. Requesting new token..."
                        # Add your next step for handling unauthorized errors here
                        $bearerToken=GetAccessToken -filePath $EnvFileName
                        Write-Host "Local variable bearerToken received from GetAccessToken function is '$bearerToken'."  # Log success message
                        GetWebhookListing -filePath $EnvFileName
                    } else {
                        Write-Host "Failed to retrieve webhooks. Status code: $statusCode"
                        Write-Host "Response content: $($response.Content)"
                        # Add your next step for other errors here
                    }
                }
            }
           
            return $null  # Return null if not found
        } 
    } else {
        Write-Error "The .env file does not exist at the specified path: $envFilePath"  # Log error if file doesn't exist
        return $null  # Return null if file doesn't exist
    }
}
function RegisterWebhook {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path of the .env file.")]
        [string]$filePath = ".env" , # Default path for the .env file
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the webhook name.")]
        [string]$webHookName,  # Webhook Name to register
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the webhook url.")]
        [string]$webHookURL,  # URL to register
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the Created By Name.")]
        [string]$createdBy,  # Registration done by
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the Security Key for your Webhook.")]
        [string]$functionKey  # Security key for the webhook
    )

    Write-Host "Inside RegisterWebhook"  # Log entry into the function

    $envFilePath = Resolve-Path "$PSScriptRoot\$filePath"  # Resolve the full path of the .env file

    if (Test-Path $envFilePath) {  # Check if the .env file exists
        if ($varName -ne "" -and $envFilePath -ne "") {  # Ensure parameters are not empty
            Write-Host "Using .env file: $envFilePath" -ForegroundColor Cyan  # Log the file being used

            # Read the contents of the .env file
            # Define the API endpoint
            $sitecoreEdgeApi = GetEnvVariable -filePath $EnvFileName -varName "SITECORE_EDGE_API"
            
            # Write-Host "Local variable bearerToken set with value '$bearerToken'."

            Write-Host "Calling Sitecore Edge API to register webhooks..."
            
            # Prepare the headers
            $headers = @{ Authorization = "Bearer $bearerToken" }

            # Prepare the body
            $body = @{
                label = $webHookName
                uri = $webHookURL
                method = "POST"
                headers = @{
                    "x-functions-key" = $functionKey
                }
                createdBy = $createdBy
                executionMode = "OnUpdate"
            } | ConvertTo-Json -Depth 10  # Convert the body to JSON            
            
            Write-Host "Calling Sitecore Edge API to register webhook..."
            Write-Host "Request Body: $body"

            try {
                $response = Invoke-WebRequest -Uri $sitecoreEdgeApi -Headers $headers -Method POST -Body $body -ContentType "application/json" -ErrorAction Stop
                $statusCode = $response.StatusCode

                # Print the raw response content
                # Write-Host "Response Content GetWebhookListing:"
                # Write-Host $response.Content                
            } catch {
                Write-Host "Error occurred in RegisterWebhook: $($_.Exception.Message)" -ForegroundColor Red

                if ($_.Exception.Response -ne $null) {
                    $statusCode = $_.Exception.Response.StatusCode
                } else {
                    throw "Unexpected error occurred in RegisterWebhook: $($_.Exception.Message)"
                }
            }
            
            # Handle the status code and execute the next step
            switch ($statusCode) {
                201 {
                    Write-Host "Webhook registered successfully. Response:"
                    Write-Host $response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
                }
                401 {
                    Write-Host "Unauthorized access 401. Please check your bearer token."
                    Write-Host "Response content: $($response.Content)"
                    Write-Warning "JWT verification failed. Requesting new token..."
                    # Add your next step for unauthorized access here
                    $bearerToken=GetAccessToken -filePath $EnvFileName
                    Write-Host "Local variable bearerToken received from GetAccessToken function is '$bearerToken'."  # Log success message
                    RegisterWebhook -filePath $filePath -webHookName $webHookName -webHookURL $webHookURL -createdBy $createdBy -functionKey $functionKey
                }
                default {
                    if ($statusCode -match "Unauthorized") {
                        Write-Host "Unauthorized error detected. Please verify your credentials or token."
                        Write-Warning "JWT verification failed. Requesting new token..."
                        # Add your next step for handling unauthorized errors here
                        $bearerToken=GetAccessToken -filePath $EnvFileName
                        Write-Host "Local variable bearerToken received from GetAccessToken function is '$bearerToken'."  # Log success message
                        RegisterWebhook -filePath $filePath -webHookName $webHookName -webHookURL $webHookURL -createdBy $createdBy -functionKey $functionKey
                    } else {
                        Write-Host "Failed to register webhook. Status code: $statusCode"
                        Write-Host "Response content: $($response.Content)"
                        # Add your next step for other errors here
                    }
                }
            }
           
            return $null  # Return null if not found
        } 
    } else {
        Write-Error "The .env file does not exist at the specified path: $envFilePath"  # Log error if file doesn't exist
        return $null  # Return null if file doesn't exist
    }
}
function GetAccessToken {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Specifies the path of the .env file.")]
        [string]$filePath = ".env"  # Default path for the .env file
    )

    Write-Host "Inside GetAccessToken"  # Log entry into the function
    $statusCodeAccessToken = 0  # Initialize status code
    $envFilePath = Resolve-Path "$PSScriptRoot\$filePath"  # Resolve the full path of the .env file

    if (Test-Path $envFilePath) {  # Check if the .env file exists
        Write-Host "Using .env file: $envFilePath" -ForegroundColor Cyan  # Log the file being used
        # Read the contents of the .env file
        $audience = GetEnvVariable -filePath $EnvFileName -varName "AUDIENCE"
        $grantType = GetEnvVariable -filePath $EnvFileName -varName "GRANT_TYPE"
        $clientId = GetEnvVariable -filePath $EnvFileName -varName "CLIENT_ID"
        $clientSecret = GetEnvVariable -filePath $EnvFileName -varName "CLIENT_SECRET"
        $sitecoreAuthApi = GetEnvVariable -filePath $EnvFileName -varName "SITECORE_AUTH_API"

        $authBody = @{
            audience = $audience
            grant_type = $grantType
            client_id = $clientId
            client_secret = $clientSecret
        } | ConvertTo-Json  # Prepare the body for the authentication request

        try {

            # Make the API call
            $response = Invoke-WebRequest -Uri $sitecoreAuthApi -Method POST -Body $authBody -ContentType "application/json" -ErrorAction Stop

            # Extract the status code
            $statusCodeAccessToken = $response.StatusCode

            # Parse the response content
            $authResponse = $response.Content | ConvertFrom-Json


            # Debug logs
            # Write-Host "Status Code Access Token: $statusCodeAccessToken"
            # Write-Host "Response Content GetAccessToken:"
            # Write-Host $authResponse

        } catch {
            Write-Host "Error occurred while getting new access token: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.Exception.Response -ne $null) {
                $statusCodeAccessToken = $_.Exception.Response.StatusCode
                $errorContent = $_.Exception.Response.GetResponseStream() | %{ $_.ReadToEnd() }
                Write-Host "Error Response Content:"
                Write-Host $errorContent
            } else {
                Write-Host "No response received from the server." -ForegroundColor Yellow
            }
            throw "Unexpected error occurred while getting new access token: $($_.Exception.Message)"
        }

        # Handle the status code and execute the next step
        switch ($statusCodeAccessToken) {
            200 {
                if ($authResponse -and $authResponse.access_token) {
                    $bearerToken = $authResponse.access_token
                    Write-Host "Successfully retrieved new access token with Status Code 200."  # Log success message
                    Write-Host "Access Token Retrieved: $bearerToken"
                } else {
                    Write-Error  "Status Code 200 - Access token not found in the response."
                }                
                return $bearerToken  # Return the new access token
            }
            "OK" {

                if ($authResponse -and $authResponse.access_token) {
                    $bearerToken = $authResponse.access_token
                    Write-Host "Successfully retrieved new access token with Status Code 200 OK"  # Log success message
                    # Write-Host "Access Token Retrieved: $bearerToken"
                } else {
                    Write-Error "Status Code OK - Access token not found in the response."
                } 

                return $bearerToken  # Return the new access token
            }
            default {
                if ($statusCodeAccessToken -match "OK") {

                    if ($authResponse -and $authResponse.access_token) {
                        $bearerToken = $authResponse.access_token
                        Write-Host "Successfully retrieved new access token with Status Code Default OK IF block"  # Log success message
                        # Write-Host "Access Token Retrieved: $bearerToken"
                    } else {
                        Write-Error "Status Code Default ELSE - Access token not found in the response."
                    }                     

                    return $bearerToken  # Return the new access token
                    } else {
                        Write-Error "Failed to retrieve new access token in Default - ELSE switch. Status code: $statusCodeAccessToken"  # Log error if not successful
                    # Add your next step for other errors here
                }
            }
        }


        if (-not $authResponse.access_token) {
            Write-Error "Failed to retrieve new access token."
            exit 1
        }
    } else {
        Write-Error "The .env file does not exist at the specified path: $envFilePath"  # Log error if file doesn't exist
        return $null  # Return null if file doesn't exist
    }
}


# Main script execution
$bearerToken = GetEnvVariable -filePath $EnvFileName -varName "BEARER_TOKEN"

if (-not $bearerToken -or [string]::IsNullOrWhiteSpace($bearerToken)) {
    Write-Host "Bearer token is null, empty, or contains only whitespace."
    # If bearerToken is null or empty then get a new token
    Write-Host "Calling GetAccessToken to get a new bearer token..."
    $bearerToken=GetAccessToken -filePath $EnvFileName
}

GetWebhookListing -filePath $EnvFileName

#RegisterWebhook -filePath $EnvFileName -webHookName "CM_HOST" -webHookURL "https://example.com/webhook" -createdBy "Admin" -functionKey "your_function_key"

#RegisterWebhook -filePath $EnvFileName -webHookName "Amit Kumar GetUpdate2" -webHookURL "https://amitkumar.com/GetUpdate2" -createdBy "Amit Kumar" -functionKey "15343"
