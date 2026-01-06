import re
import json
import sys
import os
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError
import time

# LangChain and Groq imports
try:
    from langchain_groq import ChatGroq
    from langchain_core.prompts import ChatPromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("[WARN] LangChain/Groq not available. Install with: pip install langchain-groq")

# Vulnerable patterns to check for in the source code
# These patterns check for vulnerable versions in script tags, URLs, and source code
VULNERABLE_PATTERNS = {
    # AngularJS 1.x (all versions < 1.7 are vulnerable)
    # Pattern matches: angularjs/1.3.5/angular.min.js OR angular.js?version=1.3.5 OR angular.min.js@1.3.5
    "angularjs_v1_5": r"angularjs/1\.5|angular(\.min)?\.js[^/]*1\.5",
    "angularjs_v1_4": r"angularjs/1\.4|angular(\.min)?\.js[^/]*1\.4",
    "angularjs_v1_3": r"angularjs/1\.3|angular(\.min)?\.js[^/]*1\.3",
    "angularjs_v1_2": r"angularjs/1\.2|angular(\.min)?\.js[^/]*1\.2",
    "angularjs_v1_1": r"angularjs/1\.1|angular(\.min)?\.js[^/]*1\.1",
    "angularjs_v1_0": r"angularjs/1\.0|angular(\.min)?\.js[^/]*1\.0",
    "angularjs_old": r"angularjs/1\.[0-6]|angular(\.min)?\.js[^/]*1\.[0-6]",  # Catch any 1.0-1.6
    
    # jQuery < 1.12 (vulnerable versions)
    # Pattern matches: jquery/1.11/jquery.min.js OR jquery.min.js?ver=1.11
    "jquery_old": r"jquery[^/]*1\.([0-9]|1[0-1])(\.[0-9]+)?|jquery/1\.([0-9]|1[0-1])(\.[0-9]+)?/jquery",
    
    # Bootstrap < 3.5
    "bootstrap_old": r"bootstrap[^/]*3\.[0-4]",
    
    # React < 16.8 (older versions with vulnerabilities)
    "react_old": r"react[^/]*(0\.|1[0-5]\.)|react/(0\.|1[0-5]\.)",
    
    # Vue.js < 2.6 (older versions)
    "vue_old": r"vue[^/]*(0\.|1\.|2\.[0-5])|vue\.js[^/]*(0\.|1\.|2\.[0-5])",
    
    # Backbone.js < 1.4
    "backbone_old": r"backbone[^/]*(0\.|1\.[0-3])|backbone\.js[^/]*(0\.|1\.[0-3])",
    
    # Ember.js < 2.18
    "ember_old": r"ember[^/]*(0\.|1\.|2\.[0-1][0-7])|ember\.js[^/]*(0\.|1\.|2\.[0-1][0-7])",
    
    # Knockout.js < 3.5
    "knockout_old": r"knockout[^/]*(0\.|1\.|2\.|3\.[0-4])|knockout\.js[^/]*(0\.|1\.|2\.|3\.[0-4])",
    
    # Dojo Toolkit < 1.14
    "dojo_old": r"dojo[^/]*(0\.|1\.[0-1][0-3])|dojo\.js[^/]*(0\.|1\.[0-1][0-3])",
    
    # Prototype.js < 1.7.3
    "prototype_old": r"prototype[^/]*(0\.|1\.[0-6]\.|1\.7\.[0-2])|prototype\.js[^/]*(0\.|1\.[0-6]\.|1\.7\.[0-2])",
    
    # MooTools < 1.6
    "mootools_old": r"mootools[^/]*(0\.|1\.[0-5])|mootools\.js[^/]*(0\.|1\.[0-5])",
    
    # YUI (Yahoo UI) < 3.18
    "yui_old": r"yui[^/]*(0\.|1\.|2\.|3\.[0-1][0-7])|yui\.js[^/]*(0\.|1\.|2\.|3\.[0-1][0-7])",
    
    # ExtJS < 6.2
    "extjs_old": r"extjs[^/]*(0\.|1\.|2\.|3\.|4\.|5\.|6\.[0-1])|ext\.js[^/]*(0\.|1\.|2\.|3\.|4\.|5\.|6\.[0-1])",
    
    # Underscore.js < 1.9
    "underscore_old": r"underscore[^/]*(0\.|1\.[0-8])|underscore\.js[^/]*(0\.|1\.[0-8])",
    
    # Lodash < 4.17
    "lodash_old": r"lodash[^/]*(0\.|1\.|2\.|3\.|4\.[0-1][0-6])|lodash\.js[^/]*(0\.|1\.|2\.|3\.|4\.[0-1][0-6])",
    
    # Moment.js (deprecated, all versions)
    "moment_deprecated": r"moment[^/]*\.js|moment/",
    
    # jQuery UI < 1.12
    "jquery_ui_old": r"jquery-ui[^/]*(0\.|1\.[0-1][0-1])|jqueryui[^/]*(0\.|1\.[0-1][0-1])",
    
    # WordPress (detect in meta tags, comments, or wp-content)
    "wordpress_old": r"wp-content|wordpress|wp-includes|wp-admin",
    
    # Drupal < 8 (detect in meta tags or drupal.js)
    "drupal_old": r"drupal[^/]*(0\.|6\.|7\.)|drupal\.js",
    
    # Joomla < 3.9
    "joomla_old": r"joomla[^/]*(0\.|1\.|2\.|3\.[0-8])",
    
    # ASP.NET (old versions in headers/comments)
    "aspnet_old": r"asp\.net|aspx|webforms|viewstate",
    
    # PHP (detect version in headers or comments)
    "php_old": r"php/[0-7]\.[0-9]|x-powered-by.*php/[0-7]\.[0-9]",
    
    # Ruby on Rails < 5.2
    "rails_old": r"rails[^/]*(0\.|1\.|2\.|3\.|4\.|5\.[0-1])|ruby.*on.*rails",
    
    # Django < 2.2
    "django_old": r"django[^/]*(0\.|1\.[0-1][0-1]|2\.[0-1])",
    
    # Handlebars < 4.0
    "handlebars_old": r"handlebars[^/]*(0\.|1\.|2\.|3\.)|handlebars\.js[^/]*(0\.|1\.|2\.|3\.)",
    
    # Mustache.js < 3.0
    "mustache_old": r"mustache[^/]*(0\.|1\.|2\.)|mustache\.js[^/]*(0\.|1\.|2\.)",
    
    # Marionette.js < 4.0
    "marionette_old": r"marionette[^/]*(0\.|1\.|2\.|3\.)|marionette\.js[^/]*(0\.|1\.|2\.|3\.)",
    
    # RequireJS < 2.3
    "requirejs_old": r"requirejs[^/]*(0\.|1\.|2\.[0-2])|require\.js[^/]*(0\.|1\.|2\.[0-2])",
    
    # Socket.io < 2.0
    "socketio_old": r"socket\.io[^/]*(0\.|1\.)|socketio[^/]*(0\.|1\.)",
    
    # Express.js (detect in comments/headers, < 4.17)
    "express_old": r"express[^/]*(0\.|1\.|2\.|3\.|4\.[0-1][0-6])",
    
    # Font Awesome < 5.0
    "fontawesome_old": r"font-awesome[^/]*(0\.|1\.|2\.|3\.|4\.)|fontawesome[^/]*(0\.|1\.|2\.|3\.|4\.)",
    
    # Modernizr < 3.0
    "modernizr_old": r"modernizr[^/]*(0\.|1\.|2\.)|modernizr\.js[^/]*(0\.|1\.|2\.)",
}


def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url


# Technology detection patterns (broader than vulnerability patterns)
TECH_DETECTION_PATTERNS = {
    "angularjs": r"angular(?:js|\.js|\.min\.js)",
    "angular": r"@angular/|angular\.js|angularjs",
    "react": r"react(?:\.js|\.min\.js|/)|react-dom",
    "vue": r"vue(?:\.js|\.min\.js|\.runtime)",
    "nextjs": r"_next/|next\.js|__next",
    "nuxt": r"_nuxt/|nuxt\.js",
    "svelte": r"svelte|svelte\.js",
    "jquery": r"jquery(?:\.min)?\.js",
    "backbone": r"backbone(?:\.min)?\.js",
    "ember": r"ember(?:\.js|\.min\.js)",
    "knockout": r"knockout(?:\.min)?\.js",
    "dojo": r"dojo(?:\.js|\.min\.js)",
    "prototype": r"prototype(?:\.js|\.min\.js)",
    "mootools": r"mootools(?:\.js|\.min\.js)",
    "yui": r"yui(?:\.js|\.min\.js)",
    "extjs": r"ext(?:\.js|\.min\.js)",
    "underscore": r"underscore(?:\.min)?\.js",
    "lodash": r"lodash(?:\.min)?\.js",
    "moment": r"moment(?:\.min)?\.js",
    "jquery_ui": r"jquery-ui|jqueryui",
    "bootstrap": r"bootstrap(?:\.min)?\.(js|css)",
    "wordpress": r"wp-content|wp-includes|wp-admin|wordpress",
    "drupal": r"drupal\.js|sites/default",
    "joomla": r"joomla|components/com_",
    "magento": r"magento|skin/frontend",
    "shopify": r"cdn\.shopify|shopify",
    "woocommerce": r"woocommerce",
    "aspnet": r"asp\.net|aspx|viewstate|__doPostBack",
    "php": r"\.php\?|php/|x-powered-by.*php",
    "rails": r"rails|ruby.*on.*rails|\.rb",
    "django": r"django|csrfmiddlewaretoken",
    "laravel": r"laravel|_token",
    "express": r"express|express\.js",
    "socketio": r"socket\.io",
    "handlebars": r"handlebars(?:\.min)?\.js",
    "mustache": r"mustache(?:\.min)?\.js",
    "marionette": r"marionette(?:\.min)?\.js",
    "requirejs": r"require(?:\.min)?\.js",
    "fontawesome": r"font-awesome|fontawesome",
    "modernizr": r"modernizr(?:\.min)?\.js",
}


def detect_technologies(html_content):
    """Detect technologies from HTML content."""
    html_lower = html_content.lower()
    detected_techs = []
    
    for tech_name, pattern in TECH_DETECTION_PATTERNS.items():
        if re.search(pattern, html_lower, re.IGNORECASE):
            # Try to extract version
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', html_lower)
            version = version_match.group(1) if version_match else None
            detected_techs.append({
                "name": tech_name,
                "version": version
            })
    
    return detected_techs


def format_tech_name(vulnerabilities, detected_techs=None):
    """Format technology name from vulnerabilities list or detected technologies."""
    # Map tech types to readable names
    tech_map = {
        "angularjs": "AngularJS",
        "angular": "Angular",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "react": "React",
        "vue": "Vue.js",
        "nextjs": "Next.js",
        "nuxt": "Nuxt.js",
        "svelte": "Svelte",
        "backbone": "Backbone.js",
        "ember": "Ember.js",
        "knockout": "Knockout.js",
        "dojo": "Dojo Toolkit",
        "prototype": "Prototype.js",
        "mootools": "MooTools",
        "yui": "YUI",
        "extjs": "ExtJS",
        "underscore": "Underscore.js",
        "lodash": "Lodash",
        "moment": "Moment.js",
        "jquery_ui": "jQuery UI",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "magento": "Magento",
        "shopify": "Shopify",
        "woocommerce": "WooCommerce",
        "aspnet": "ASP.NET",
        "php": "PHP",
        "rails": "Ruby on Rails",
        "django": "Django",
        "laravel": "Laravel",
        "handlebars": "Handlebars",
        "mustache": "Mustache.js",
        "marionette": "Marionette.js",
        "requirejs": "RequireJS",
        "socketio": "Socket.io",
        "express": "Express.js",
        "fontawesome": "Font Awesome",
        "modernizr": "Modernizr",
    }
    
    # First, try to get tech from vulnerabilities
    if vulnerabilities:
        first_vuln = vulnerabilities[0]
        tech_type = first_vuln.get("type", "")
        version = first_vuln.get("version", "unknown")
        
        tech_name = "Unknown"
        for key, name in tech_map.items():
            if key in tech_type.lower():
                tech_name = name
                break
        
        if version != "unknown":
            tech_name = f"{tech_name} {version}"
        
        return tech_name
    
    # If no vulnerabilities, use detected technologies
    if detected_techs:
        # Prioritize frameworks over libraries
        priority_order = ["react", "vue", "angular", "angularjs", "nextjs", "nuxt", "svelte", 
                        "wordpress", "drupal", "joomla", "magento", "shopify", "rails", 
                        "django", "laravel", "aspnet", "php", "express"]
        
        for priority_tech in priority_order:
            for tech in detected_techs:
                if tech["name"] == priority_tech:
                    tech_name = tech_map.get(priority_tech, priority_tech.title())
                    if tech["version"]:
                        tech_name = f"{tech_name} {tech['version']}"
                    return tech_name
        
        # If no priority tech found, use first detected
        first_tech = detected_techs[0]
        tech_name = tech_map.get(first_tech["name"], first_tech["name"].title())
        if first_tech["version"]:
            tech_name = f"{tech_name} {first_tech['version']}"
        return tech_name
    
    return "Unknown"


def format_load_time(fcp_ms):
    """Format load time from milliseconds to seconds string."""
    if fcp_ms is None:
        return "N/A"
    seconds = fcp_ms / 1000.0
    return f"{seconds:.1f}s"


def diagnose_site(url):
    """
    Diagnose a website for console errors, load speed, and vulnerabilities.
    
    Returns a JSON object with:
    - url: The tested URL
    - console_errors: List of console error messages
    - first_contentful_paint_ms: FCP time in milliseconds
    - vulnerabilities: List of detected vulnerable patterns
    - status: Overall status (clean, at_risk, timeout, error)
    """
    result = {
        "url": url,
        "console_errors": [],
        "first_contentful_paint_ms": None,
        "vulnerabilities": [],
        "status": "unknown"
    }

    print(f"[INFO] Starting diagnosis for {url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Capture console errors
        def handle_console(msg):
            if msg.type == "error":
                error_text = msg.text
                # Also capture location if available
                location = ""
                if msg.location:
                    location = f" ({msg.location['url']}:{msg.location.get('lineNumber', '?')})"
                result["console_errors"].append(error_text + location)

        page.on("console", handle_console)

        html = ""
        detected_techs = []
        
        try:
            # Navigate - try networkidle first, fallback to domcontentloaded
            try:
                page.goto(url, wait_until="networkidle", timeout=30000)
                print("[INFO] Page loaded (networkidle)")
            except TimeoutError:
                # If networkidle times out, try domcontentloaded to at least get HTML
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    print("[INFO] Page loaded (domcontentloaded - partial)")
                except TimeoutError:
                    # Even if timeout, try to get whatever HTML is available
                    print("[WARN] Page load timeout, attempting to get HTML...")
                    pass

            # Get HTML content as early as possible for tech detection
            try:
                html = page.content()
                detected_techs = detect_technologies(html)
                if detected_techs:
                    print(f"[INFO] Detected technologies: {[t['name'] for t in detected_techs[:3]]}")
            except Exception as e:
                print(f"[WARN] Could not get HTML content: {e}")

            # Wait a bit for performance entries to be available
            time.sleep(1)

            # Measure First Contentful Paint (FCP)
            fcp = page.evaluate("""
                () => {
                    return new Promise((resolve) => {
                        // Check if FCP is already available
                        const entries = performance.getEntriesByType('paint');
                        const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
                        
                        if (fcpEntry) {
                            resolve(Math.round(fcpEntry.startTime));
                        } else {
                            // Wait for FCP if not available yet
                            const observer = new PerformanceObserver((list) => {
                                const entries = list.getEntries();
                                const fcpEntry = entries.find(entry => entry.name === 'first-contentful-paint');
                                if (fcpEntry) {
                                    observer.disconnect();
                                    resolve(Math.round(fcpEntry.startTime));
                                }
                            });
                            
                            try {
                                observer.observe({ entryTypes: ['paint'] });
                                // Timeout after 5 seconds
                                setTimeout(() => {
                                    observer.disconnect();
                                    resolve(null);
                                }, 5000);
                            } catch (e) {
                                resolve(null);
                            }
                        }
                    });
                }
            """)

            result["first_contentful_paint_ms"] = fcp
            if fcp:
                print(f"[INFO] FCP: {fcp}ms")
            else:
                print("[WARN] FCP measurement unavailable")

            # Get page source for vulnerability scanning (if not already got)
            if not html:
                try:
                    html = page.content()
                except:
                    html = ""
            
            html_lower = html.lower() if html else ""

            # Track found vulnerabilities to avoid duplicates
            found_vulns = set()
            
            # Check for vulnerable patterns (check specific versions first, then generic)
            # Order matters: check specific versions before generic patterns
            pattern_order = sorted(VULNERABLE_PATTERNS.items(), 
                                 key=lambda x: ('old' in x[0], x[0]))
            
            for tech, pattern in pattern_order:
                matches = re.finditer(pattern, html_lower, re.IGNORECASE)
                for match in matches:
                    # Extract version number from the match context
                    match_start = max(0, match.start() - 50)
                    match_end = min(len(html_lower), match.end() + 50)
                    context = html_lower[match_start:match_end]
                    
                    # Try to find version number in the context
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', context)
                    version = version_match.group(1) if version_match else "unknown"
                    
                    # Create a unique key for this vulnerability
                    # For AngularJS, use the actual version instead of pattern name
                    if 'angularjs' in tech:
                        vuln_key = f"angularjs_{version}"
                    elif 'jquery' in tech and 'ui' not in tech:
                        # Skip jQuery plugins (files that aren't jquery.js or jquery.min.js)
                        matched_text = html[match.start():match.end()][:100].lower()
                        # Only flag if it's actually jquery.js or jquery.min.js, not plugins
                        if not ('jquery.js' in matched_text or 'jquery.min.js' in matched_text or 
                                'jquery/' in matched_text or '/jquery' in matched_text):
                            continue
                        vuln_key = f"jquery_{version}"
                    elif 'wordpress' in tech or 'drupal' in tech or 'joomla' in tech:
                        # CMS frameworks - use tech name as key
                        vuln_key = tech
                    elif 'php' in tech or 'aspnet' in tech or 'rails' in tech or 'django' in tech:
                        # Backend frameworks - use tech name and version
                        vuln_key = f"{tech}_{version}" if version != "unknown" else tech
                    else:
                        # Other frameworks - use tech name and version
                        vuln_key = f"{tech}_{version}" if version != "unknown" else tech
                    
                    # Skip if we've already found this vulnerability
                    if vuln_key in found_vulns:
                        continue
                    
                    found_vulns.add(vuln_key)
                    
                    # Extract the actual matched text for reference
                    matched_text = html[match.start():match.end()][:100]  # First 100 chars
                    
                    result["vulnerabilities"].append({
                        "type": tech,
                        "version": version,
                        "matched_text": matched_text
                    })
                    print(f"[WARN] Found vulnerability: {tech} (version: {version})")
                    break  # Only report once per pattern type

            # Determine overall status
            if result["console_errors"] or result["vulnerabilities"]:
                result["status"] = "at_risk"
            elif fcp and fcp > 3000:  # FCP > 3 seconds is considered slow
                result["status"] = "at_risk"
            else:
                result["status"] = "clean"

            print(f"[INFO] Status: {result['status']}")
            if result["console_errors"]:
                print(f"[INFO] Found {len(result['console_errors'])} console errors")
            if result["vulnerabilities"]:
                print(f"[INFO] Found {len(result['vulnerabilities'])} vulnerabilities")

        except TimeoutError:
            print("[ERROR] Page load timeout")
            result["status"] = "timeout"
            result["error"] = "Page load timeout after 30 seconds"
            # Try to get HTML even on timeout for tech detection
            try:
                html = page.content()
                detected_techs = detect_technologies(html)
                if detected_techs:
                    print(f"[INFO] Detected technologies (timeout): {[t['name'] for t in detected_techs[:3]]}")
            except:
                pass

        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            # Try to get HTML even on error for tech detection
            try:
                html = page.content()
                detected_techs = detect_technologies(html)
            except:
                pass

        finally:
            browser.close()

    # Add new fields to result
    result["domain"] = extract_domain(url)
    result["tech"] = format_tech_name(result["vulnerabilities"], detected_techs)
    result["console_error_count"] = len(result["console_errors"])
    result["load_time"] = format_load_time(result["first_contentful_paint_ms"])
    result["vulnerability_detected"] = len(result["vulnerabilities"]) > 0

    return result


def generate_technical_observation(result):
    """
    Generate a technical observation using Groq/LangChain.
    
    Args:
        result: Diagnosis result dictionary
    
    Returns:
        Technical observation string or None if generation fails
    """
    if not LANGCHAIN_AVAILABLE:
        return None
    
    # Get Groq API key from environment
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        print("[WARN] GROQ_API_KEY not set. Skipping technical observation generation.")
        return None
    
    try:
        # Extract data from result
        tech = result.get("tech", "Unknown")
        error_count = result.get("console_error_count", 0)
        load_time = result.get("load_time", "N/A")
        
        # Create the LLM
        llm = ChatGroq(
            groq_api_key=groq_api_key,
            model_name="llama-3.1-70b-versatile",
            temperature=0.3
        )
        
        # Create the prompt template
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a Senior Technical Architect. You are analyzing a prospective client's website.

They are running {tech} which is End-of-Life.

They have {error_count} console errors and a load time of {load_time}.

Write a specific, 2-sentence 'Technical Observation' about why this is dangerous for their business (focus on security or lost revenue). Do NOT be salesy. Be clinical."""),
            ("human", "Generate the technical observation.")
        ])
        
        # Create the chain
        chain = prompt | llm
        
        # Generate the observation
        print("[INFO] Generating technical observation with Groq...")
        response = chain.invoke({
            "tech": tech,
            "error_count": error_count,
            "load_time": load_time
        })
        
        observation = response.content.strip()
        print(f"[INFO] Technical observation generated")
        return observation
        
    except Exception as e:
        print(f"[ERROR] Failed to generate technical observation: {e}")
        return None


def diagnose_multiple_sites(urls, generate_observations=True):
    """
    Diagnose multiple websites and return results for each.
    
    Args:
        urls: List of URLs to diagnose
        generate_observations: Whether to generate technical observations using Groq
    
    Returns:
        List of diagnosis results (JSON objects)
    """
    results = []
    for url in urls:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = diagnose_site(url)
        
        # Generate technical observation if requested and vulnerabilities detected
        if generate_observations and result.get("vulnerability_detected", False):
            observation = generate_technical_observation(result)
            if observation:
                result["technical_observation"] = observation
        
        results.append(result)
        print()  # Empty line between results
    
    return results


if __name__ == "__main__":
    # Default URL if none provided
    TARGET_URLS = ["https://algofolks.com/"]
    
    # Allow URLs to be passed as command line arguments
    if len(sys.argv) > 1:
        TARGET_URLS = sys.argv[1:]
    
    print("=" * 60)
    print("Website Diagnosis Tool")
    print("=" * 60)
    print(f"Checking {len(TARGET_URLS)} domain(s)...\n")
    
    # Diagnose all sites
    all_results = diagnose_multiple_sites(TARGET_URLS)
    
    # Output JSON results
    print("\n" + "=" * 60)
    print("FINAL RESULTS (JSON)")
    print("=" * 60)
    
    if len(all_results) == 1:
        # Single result - output as single object
        print(json.dumps(all_results[0], indent=2))
    else:
        # Multiple results - output as array
        print(json.dumps(all_results, indent=2))
    
    # Also save to file
    output_file = "diagnosis_results.json"
    with open(output_file, 'w') as f:
        if len(all_results) == 1:
            json.dump(all_results[0], f, indent=2)
        else:
            json.dump(all_results, f, indent=2)
    
    print(f"\n[INFO] Results also saved to {output_file}")


