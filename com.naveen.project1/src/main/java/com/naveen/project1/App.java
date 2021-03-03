package com.naveen.project1;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import org.apache.xpath.XPathAPI;
import org.cyberneko.html.parsers.DOMParser;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.naveen.project1.RobotsText;

public class App 
{
    public static void main( String[] args ) 
    {
    		String link = args[0];
    		String filename = args[1];
    		if(link != null){
    			try
    			{
    				// checking robots.txt file for the give link which is available for every domain
	            boolean allow_robotstxt=RobotsText.allows(link);
	            if(allow_robotstxt)
	            {
	            		JSONObject obj = RobotsText.getLinkContent(link);
	            		byte[] data  = (byte[]) obj.get("data");
	            		if(data != null)
	            		{
	            			String content = new String(data);
	            			//printing title in command prompt
	            			String title = null;
	            			DOMParser parser=new DOMParser();
	            			ByteArrayInputStream bis=new ByteArrayInputStream(content.getBytes());
	            			InputSource isource=new InputSource(bis);
	            			try{
	            				parser.setFeature("http://xml.org/sax/features/namespaces",false); 
	            				parser.setProperty("http://cyberneko.org/html/properties/default-encoding", "utf-8"); 
	            				parser.parse(isource);
	            			}catch(IOException e) {
	            				e.printStackTrace();
	            			}catch(SAXException e) {
	            				e.printStackTrace();
	            			}
	            			org.w3c.dom.Document doc=parser.getDocument();
	            			Element docElement = doc.getDocumentElement();

	            			Node titleTagNode = XPathAPI.selectSingleNode(docElement, "//HEAD/TITLE"); 
	            			if(titleTagNode != null){
	            				title = titleTagNode.getTextContent();
	            			}

	            			if(title == null || "".equals(title.trim())){
	            				Node titleNode = XPathAPI.selectSingleNode(docElement, "//HEAD/descendant::META[@name='title']"); 
	            				if(titleNode != null && titleNode.getAttributes().getNamedItem("content") != null){ 
	            					title = titleNode.getAttributes().getNamedItem("content").getTextContent(); 
	            				}
	            			}

	            			if(title == null || "".equals(title.trim())){
	            				Node titleNode = XPathAPI.selectSingleNode(docElement, "//HEAD/descendant::META[@property='og:title']"); 
	            				if(titleNode != null && titleNode.getAttributes().getNamedItem("content") != null){ 
	            					title = titleNode.getAttributes().getNamedItem("content").getTextContent(); 
	            				}
	            			}

	            			if(title == null || "".equals(title.trim())){
	            				Node titleNode = XPathAPI.selectSingleNode(docElement, "//HEAD/descendant::META[@name='twitter:title']"); 
	            				if(titleNode != null && titleNode.getAttributes().getNamedItem("content") != null){ 
	            					title = titleNode.getAttributes().getNamedItem("content").getTextContent(); 
	            				}
	            			}
	            			System.out.println("Title:"+title);
	            			try {
	    				        FileWriter myWriter = new FileWriter(filename,true);
	    				        BufferedWriter bw = new BufferedWriter(myWriter);
	    				        PrintWriter out = new PrintWriter(bw);
	    				        out.print(content);
	    				        out.println();
	    				        out.close();
	    				        System.out.println("successfully wrote to the file");
	    					}catch(Exception e){
	    						e.printStackTrace();
	    					}
	            		}
	            }
    			}catch(Exception e)
    			{
    				System.out.println("Exception:"+e);  
    			}
    		}
    }
}
