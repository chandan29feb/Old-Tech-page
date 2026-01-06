# Website Diagnosis Tool

A comprehensive tool to diagnose websites for vulnerabilities, performance issues, and technical problems.

## Features

- 🔍 **Technology Detection**: Identifies frameworks and libraries (React, Vue, Angular, WordPress, etc.)
- 🛡️ **Vulnerability Scanning**: Detects outdated and vulnerable versions of popular frameworks
- ⚡ **Performance Metrics**: Measures First Contentful Paint (FCP) load time
- 🐛 **Console Error Detection**: Captures JavaScript console errors
- 🤖 **AI-Powered Analysis**: Generates technical observations using Groq/LangChain
- 💾 **Smart File Naming**: Saves results with URL-based filenames for easy identification

## Installation

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
playwright install chromium
```

3. (Optional) Set up Groq API key for technical observations:
```bash
export GROQ_API_KEY="your-api-key-here"
```

## Usage

### Web UI (Recommended)

Start the Flask web server:
```bash
python app.py
```

Then open your browser to: `http://localhost:5000`

Enter a URL and click "Diagnose" to see results in a beautiful web interface.

### Command Line

```bash
python diagnose_website.py https://example.com
```

Results are saved to `diagnosis_results.json`

For multiple URLs:
```bash
python diagnose_website.py https://example.com https://another-site.com
```

## Output Files

Results are saved in the `results/` directory with filenames based on the domain:
- `diagnosis_example_com.json`
- `diagnosis_algofolks_com.json`

## Output Format

```json
{
  "domain": "example.com",
  "tech": "AngularJS 1.3.5",
  "console_error_count": 3,
  "load_time": "4.2s",
  "vulnerability_detected": true,
  "vulnerabilities": [...],
  "console_errors": [...],
  "technical_observation": "..."
}
```

## Technologies Detected

- Frontend: React, Vue, Angular, Next.js, Nuxt, Svelte
- CMS: WordPress, Drupal, Joomla, Magento, Shopify
- Backend: Rails, Django, Laravel, ASP.NET, PHP, Express
- Libraries: jQuery, Bootstrap, Socket.io, and 30+ more

## License

MIT

