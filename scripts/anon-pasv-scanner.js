/**
 * This script checks whether resources (URLs) are successfully accessed (Status 200 - Ok)
 * on a request which did not have an authorization header.
 *
 * Note: This is a passive script not an active script: As such the Authorization header 
 * is not forcefully removed prior to making the request. This script will only alert if a 
 * request is proxied (or initiated via the spider(s), etc) which does not have an Authorization
 * header, and subsequently passively scanned.
 * Source: https://github.com/zaproxy/zaproxy/issues/4602#issuecomment-382106798
 */

 function scan(ps, msg, src) 
 {
     const alertRisk = 1
     const alertReliability = 2
     const alertTitle = "Resource Allows Anonymous Access"
     const alertDesc = "The web/application server allowed access without any Authorization header on the request."
     const alertSolution = "Ensure that the application appropriately requires authentication and authorization."
 
     const cweId = 0
     const wascId = 0
 
     let url = msg.getRequestHeader().getURI().toString();
     let headers = msg.getRequestHeader().getHeaders("Authorization");
     
     // Might want to check here to see if the URL is in scope: msg.isInScope()
     if (headers == null && msg.getResponseHeader().getStatusCode() == 200)
     {
         ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution, headers, cweId, wascId, msg);
     }
     
 }
