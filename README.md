# txhunter_connector
This app integrates with TriagingX TXHunter to support forensic investigate actions.

The Asset settings of Configuration:

1. URL: The portal of TXHunter.

2. APIKey: Login your account on TXHunter portal, go to API Key tab in Config section, add a API Key, copy and paste the new added API Key here.

3. User: The user that created the API Key.

4. Organization: Login your account on TXHunter portal, go to Organization tab in Config section, add an Organization and bind to above user, put the new added Organization name here, this organization will do the same as the selected organization when manually downloading the agent on TXHunter portal.

The parameters of Configuration:

1. ip hostname: The ip hostname / url of endpoint to do actions, this is required.

2. the other parameters are optional, they are used for the Windows Remote Management service

This app supports forensic investigate actions on both TXHunter managed agent and online agent.

1. managed agent:

a. If the endpoint has pre-installed TXHunter managed agent, and the TGXService is running, when doing forensic investigation on this kind of endpoints, only the ip hostname of parameters is required.

b. If the endpoint has pre-installed TXHunter managed agent, but the TGXService is not running, when doing forensic investigation on this kind of endpoints, besides the ip hostname, the other parameters should be specified for the Windows Remote Management service.

2. online agent:

a. If the endpoint is not installed TXHunter managed agent, when doing forensic investigation on this kind of endpoints, besides the ip hostname, the other parameters should be specified for the Windows Remote Management service.

If the endpoint is not installed TXHunter managed agent and has activated (TGXService is running), then the Windows Remote Management(WinRM) should be enabled on these endpoints for the app to run commands remotely. In order to do forensic investigate actions, you must have the Windows Remote Management service running on the endpoint you wish to connect to. For help regarding this process, consult this link: https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx
