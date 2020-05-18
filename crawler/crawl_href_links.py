from bs4 import BeautifulSoup 
import requests
import urlparse
import argparse

# set, to avoid duplicates
urls = set() 

def crawl(site): 
    # getting the request from url
    if not site:
        return 
    r = requests.get(site) 
    # converting the text 
    s = BeautifulSoup(r.content, "html.parser") 
    for i in s.find_all("a"): 
        href = i.get('href')
        site = urlparse.urljoin(site, href)
    # avoid crawling external web pages referred 
    if domain not in site:
        return
        if site not in urls: 
            urls.add(site)  
            print(site) 
            crawl(site)

# main function 
if __name__ =="__main__": 
    # website to be crawl 
    parser = argparse.ArgumentParser(description='Find urls referenced within the given webpage')
    parser.add_argument('-u', '--url', dest="web_site", help="web page link", required=True)
    args = parser.parse_args()
    domain = urlparse.urlparse(args.web_site).netloc
    # calling function 
    crawl(args.web_site)
