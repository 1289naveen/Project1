package com.naveen.project1;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;

public class RobotsText {
	public static boolean allows(String link) throws IOException
	{
		int timeout=0;
		 URL url = new URL(link);
	        String path = url.getPath();
	        String strurl=null;
	        if(link.contains("?") && !path.contains("?"))
	        {
	        	int indexof =link.indexOf("?");
	        	strurl=link.substring(indexof);
	        	path=path+strurl;
	        }
	        String hostdomain = url.getHost();
			 if(hostdomain.startsWith("www.")){
					hostdomain=hostdomain.substring(4);
				}
			String domainkey = "robotstxt_"+hostdomain;
			domainkey = domainkey.toLowerCase();
	        HostDirectives directives=null;
	        JSONObject obj = fetchDirectives(url);
	        directives = (HostDirectives) obj.get("directives");
	        if(directives ==null)
	        {
	        	return true;
	        }
	        Boolean allows= directives.allows(path);
	    return allows;
	        
	}

	public static JSONObject fetchDirectives(URL url) {
		 String robotsTxtUrl =null;
		 int timeout = 0;
		 JSONObject obj = new JSONObject();
		    String host = url.getHost().toLowerCase();
		    String port = ((url.getPort() == url.getDefaultPort()) || (url.getPort() == -1)) ? "" : (":" + url.getPort());
		    robotsTxtUrl=url.getProtocol()+"://" + host + port + "/robots.txt";
		    HostDirectives directives = null;
		    byte[] data = null;
		    JSONObject obj1 = getLinkContent(robotsTxtUrl);
			data = (byte[]) obj1.get("data");
		    if(data ==null)
		    {
		    	obj.put("directives",data);
		    	return obj;
		    }
		    String content=new String(data);
		    directives = RobotstxtParser.parse(content);
		    obj.put("directives",directives);
	    return obj;
	}
	
	public static JSONObject getLinkContent(String link){
		
		JSONObject obj = new JSONObject();
		byte[] data = null;
		try{
			URL url = new URL(link);
			
			if(link.startsWith("https")){ 
                HttpsURLConnection connection=(HttpsURLConnection)url.openConnection();
                connection.setConnectTimeout(3000);
                connection.setDoInput(true);
                connection.setDoOutput(false);
                connection.setRequestMethod("GET"); 
                connection.setAllowUserInteraction(false); 
                connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");  
                connection.connect();
                //printing headers 
                Map<String, List<String>> map = connection.getHeaderFields();
                for (Map.Entry<String, List<String>> entry : map.entrySet()) {
                    System.out.println("Key : " + entry.getKey() + 
                             " ,Value : " + entry.getValue());
                }
                InputStream istream = connection.getInputStream();
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte a[]= new byte[512];
                int read = -1;
                while((read = istream.read(a)) != -1){
                    bos.write(a, 0, read);
                }
                istream.close();
                connection.disconnect();
                data = bos.toByteArray();
                bos.close();
            } else {
                HttpURLConnection connection=(HttpURLConnection)url.openConnection();
                connection.setConnectTimeout(3000);
                connection.setDoInput(true);
                connection.setDoOutput(false);
                connection.setRequestMethod("GET"); 
                connection.setAllowUserInteraction(false); 
                connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");  
                connection.connect();
                
                //printing headers 
                Map<String, List<String>> map = connection.getHeaderFields();
                for (Map.Entry<String, List<String>> entry : map.entrySet()) {
                    System.out.println("Key : " + entry.getKey() + 
                             " ,Value : " + entry.getValue());
                }
                
                InputStream istream = connection.getInputStream();
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte a[]= new byte[512];
                int read = -1;
                while((read = istream.read(a)) != -1){
                    bos.write(a, 0, read);
                }
                istream.close();
                data = bos.toByteArray();
                connection.disconnect();
                bos.close();
            }
		}catch(Exception e){
			System.out.println("Exception while getting data from link : "+ e);
		}
		obj.put("data", data);
		return obj;
	
	}

}
class HostDirectives{
	
    public static final int ALLOWED = 1;
    public static final int DISALLOWED = 2;
    public static final int UNDEFINED = 3;
    private Set<UserAgentDirectives> rules;
    private String userAgentName;
    public HostDirectives(String userAgentName)
    {
    	this.userAgentName=userAgentName;
    	rules = new TreeSet<UserAgentDirectives>(
                new UserAgentDirectives.UserAgentComparator(userAgentName));
    }
    public boolean allows(String path) {
        return checkAccess(path) != DISALLOWED;
    }
	public int checkAccess(String path) {
		
		int result = UNDEFINED;
		for (UserAgentDirectives ua : rules) {
            int score = ua.match(userAgentName);

            // If ignoreUADisc is disabled and the current UA doesn't match,
            // the rest will not match so we are done here.
            if (score == 0) {
                break;
            }

            // Match the rule to the path
            result = ua.checkAccess(path, userAgentName);

            // If the result is ALLOWED or UNDEFINED, or if
            // this is a wildcard rule and ignoreUADisc is disabled,
            // this is the final verdict.
            if (result != DISALLOWED || (!ua.isWildcard())) {
                break;
            }

            // This is a wildcard rule that disallows access. The verdict is stored,
            // but the other rules will also be checked to see if any specific UA is allowed
            // access to this path. If so, that positive UA discrimination is ignored
            // and we crawl the page anyway.
        }
        return result;
	}
	public void addDirectives(UserAgentDirectives directives) {
        rules.add(directives);
    }
	
}
class RobotstxtParser {
	    private static final Pattern RULE_PATTERN = Pattern.compile("(?i)^([A-Za-z\\-]+):(.*)");
	    private static final Set<String> VALID_RULES = new HashSet<String>(
	    Arrays.asList("allow", "disallow", "user-agent", "crawl-delay", "host", "sitemap"));
	    public static HostDirectives parse(String content) {
	    	 HostDirectives directives = new HostDirectives("Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; en-US; rv:1.9.2.2) Gecko/20100316 Firefox/3.6.2");
	    	 StringTokenizer st = new StringTokenizer(content, "\n\r");
	         Set<String> userAgents = new HashSet<String>();
	         UserAgentDirectives uaDirectives = null;
	         while (st.hasMoreTokens()) {
	             String line = st.nextToken();

	             // Strip comments
	             int commentIndex = line.indexOf('#');
	             if (commentIndex > -1) {
	                 line = line.substring(0, commentIndex);
	             }

	             // remove any html markup
	             line = line.replaceAll("<[^>]+>", "").trim();
	             if (line.isEmpty()) {
	                 continue;
	             }

	             Matcher m = RULE_PATTERN.matcher(line);
	             if (m.matches()) {
	                 String rule = m.group(1).toLowerCase();
	                 String value = m.group(2).trim();
	                 if (VALID_RULES.contains(rule)) {
	                     if (rule.equals("user-agent")) {
	                         String currentUserAgent = value.toLowerCase();
	                         if (uaDirectives != null) {
	                             // If uaDirectives is not null, this means that one or
	                             // more rules followed the User-agent: definition list
	                             // In that case, it's not allowed to add more user-agents,
	                             // so this is an entirely new set of directives.
	                             userAgents = new HashSet<String>();
	                             directives.addDirectives(uaDirectives);
	                             uaDirectives = null;
	                         }
	                         userAgents.add(currentUserAgent);
	                     } else {
	                         if (uaDirectives == null) {
	                             // No "User-agent": clause defaults to
	                             // wildcard UA
	                             if (userAgents.isEmpty()) {
	                                 userAgents.add("*");
	                             }
	                             uaDirectives = new UserAgentDirectives(userAgents);
	                         }
	                         uaDirectives.add(rule, value);
	                     }
	                 } else {
	                	 System.out.println("Unrecognized rule in robots.txt:"+rule);
	                 }
	             } else {
	            	 	System.out.println("Unrecognized line in robots.txt"+line);
	             }
	         }

	         if (uaDirectives != null) {
	             directives.addDirectives(uaDirectives);
	         }
	         return directives;
	    	
	    }

}
class UserAgentDirectives{
	public Set<String> userAgents;
    private List<String> sitemap = null;
    private Set<PathRule> pathRules = new HashSet<>();
    static class PathComparator implements Comparator<PathRule> {
        /** The path to compare the path rules with */
        String path;

        /** Initialize with the path */
        PathComparator(String path) {
            this.path = path;
        }
        @Override
        public int compare(PathRule lhs, PathRule rhs) {
           /* boolean p1Match = lhs.matches(path);
            boolean p2Match = rhs.matches(path);

            // Matching patterns come first
            if (p1Match && !p2Match) {
                return -1;
            } else if (p2Match && !p1Match) {
                return 1;
            }*/

            // Most specific pattern first
            String p1 = lhs.pattern.toString();
            String p2 = rhs.pattern.toString();

            if (p1.length() != p2.length()) {
                return Integer.compare(p2.length(), p1.length());
            }

            // Just order alphabetically if the patterns are of the same length
            return p1.compareTo(p2);
        }
    }

    public UserAgentDirectives(Set<String> userAgents) {
        this.userAgents = userAgents;
    }
    public int match(String userAgent) {
        userAgent = userAgent.toLowerCase();
        int maxLength = 0;
        for (String ua : userAgents) {
            if (ua.equals("*") || userAgent.contains(ua)) {
                maxLength = Math.max(maxLength, ua.length());
            }
        }
        return maxLength;
    }
    public boolean isWildcard() {
        return userAgents.contains("*");
    }
    public int checkAccess(String path, String userAgent) {
        // If the user agent does not match, the verdict is known
        if (match(userAgent) == 0) {
            return HostDirectives.UNDEFINED;
        }

        // Order the rules based on their match with the path
        Set<PathRule> rules = new TreeSet<>(new PathComparator(path));
        rules.addAll(pathRules);
        // Return the verdict of the best matching rule
        for (PathRule rule : rules) {
            if (rule.matches(path)) {
                return rule.type;
            }
        }

        return HostDirectives.UNDEFINED;
    }
    public static class UserAgentComparator implements Comparator<UserAgentDirectives> {
        String crawlUserAgent;

        UserAgentComparator(String myUA) {
            crawlUserAgent = myUA;
        }

        @Override
        public int compare(UserAgentDirectives lhs, UserAgentDirectives rhs) {
            int matchLhs = lhs.match(crawlUserAgent);
            int matchRhs = rhs.match(crawlUserAgent);
            if (matchLhs != matchRhs) {
                return Integer.compare(matchRhs, matchLhs); // Sort descending
            }

            // Return the shortest list of user-agents unequal
            if (lhs.userAgents.size() != rhs.userAgents.size()) {
                return Integer.compare(lhs.userAgents.size(), rhs.userAgents.size());
            }

            // Alphabetic sort when length of lists is equal
            Iterator<String> i1 = lhs.userAgents.iterator();
            Iterator<String> i2 = rhs.userAgents.iterator();

            // Find first non-equal user agent
            while (i1.hasNext()) {
                String ua1 = i1.next();
                String ua2 = i2.next();
                int order = ua1.compareTo(ua2);
                if (order != 0) {
                    return order;
                }
            }

            // List of user agents was also equal, so these directives are equal
            return 0;
        }
    }

    public void add(String rule, String value) {
        if (rule.equals("sitemap")) {
            if (this.sitemap == null) {
                this.sitemap = new ArrayList<String>();
            }
            this.sitemap.add(value);
        }else if (rule.equals("allow")) {
            this.pathRules.add(new PathRule(HostDirectives.ALLOWED, value));
        } else if (rule.equals("disallow")) {
            this.pathRules.add(new PathRule(HostDirectives.DISALLOWED, value));
        } else {
        System.out.println("Invalid key in robots.txt passed to UserAgentRules"+rule);
        }
    }
}
class PathRule{
	public int type;
    public Pattern pattern;
    public static Pattern robotsPatternToRegexp(String pattern) {
        StringBuilder regexp = new StringBuilder();
        regexp.append('^');
        StringBuilder quoteBuf = new StringBuilder();
        boolean terminated = false;

        // If the pattern is empty, match only completely empty entries, e.g., none as
        // there will always be a leading forward slash.
        if (pattern.isEmpty()) {
            return Pattern.compile("^$");
        }

        // Iterate over the characters
        for (int pos = 0; pos < pattern.length(); ++pos) {
            char ch = pattern.charAt(pos);

            if (ch == '\\') {
                // Handle escaped * and $ characters
                char nch = pos < pattern.length() - 1 ? pattern.charAt(pos + 1) : 0;
                if (nch == '*' || ch == '$') {
                    quoteBuf.append(nch);
                    ++pos; // We need to skip one character
                } else {
                    quoteBuf.append(ch);
                }
            } else if (ch == '*') {
                // * indicates any sequence of one or more characters
                if (quoteBuf.length() > 0) {
                    // The quoted character buffer is not empty, so add them before adding
                    // the wildcard matcher
                    regexp.append("\\Q").append(quoteBuf).append("\\E");
                    quoteBuf = new StringBuilder();
                }
                if (pos == pattern.length() - 1) {
                    terminated = true;
                    // A terminating * may match 0 or more characters
                    regexp.append(".*");
                } else {
                    // A non-terminating * may match 1 or more characters
                    regexp.append(".+");
                }
            } else if (ch == '$' && pos == pattern.length() - 1) {
                // A $ at the end of the pattern indicates that the path should end here in order
              // to match
                // This explicitly disallows prefix matching
                if (quoteBuf.length() > 0) {
                    // The quoted character buffer is not empty, so add them before adding
                    // the end-of-line matcher
                    regexp.append("\\Q").append(quoteBuf).append("\\E");
                    quoteBuf = new StringBuilder();
                }
                regexp.append(ch);
                terminated = true;
            } else {
                // Add the character as-is to the buffer for quoted characters
                quoteBuf.append(ch);
            }
        }

        // Add quoted string buffer: enclosed between \Q and \E
        if (quoteBuf.length() > 0) {
            regexp.append("\\Q").append(quoteBuf).append("\\E");
        }

        // Add a wildcard pattern after the path to allow matches where this
        // pattern matches a prefix of the path.
        if (!terminated) {
            regexp.append(".*");
        }

        // Return the compiled pattern
        return Pattern.compile(regexp.toString());
    }
	public PathRule(int type, String pattern) {
        this.type = type;
        this.pattern = robotsPatternToRegexp(pattern);
    }
	public boolean matches(String path) {
	  boolean isMatches = false;
	  try {
	    isMatches = this.pattern.matcher(path).matches();
	  }catch(Exception e) {
	    StringBuilder sb = new StringBuilder();
	    sb.append("Taking long time for regex process in Robots.txt, pattern : "); 
	    sb.append(this.pattern.toString());
	    sb.append(" string : "); 
	    sb.append(path);
	    System.out.println(sb.toString());
	  }
        return isMatches;
    }
}

