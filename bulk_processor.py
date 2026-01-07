"""
Bulk Processing Module
Handles background processing of multiple URLs with progress tracking.
"""
import threading
import time
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
from diagnose_website import diagnose_site, generate_technical_observation


class BulkProcessor:
    """Manages bulk URL processing jobs with progress tracking."""
    
    def __init__(self):
        self.jobs: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def create_job(self, urls: List[str], generate_observations: bool = False) -> str:
        """
        Create a new bulk processing job.
        
        Args:
            urls: List of URLs to process
            generate_observations: Whether to generate technical observations
        
        Returns:
            Job ID string
        """
        job_id = f"job_{int(time.time() * 1000)}"
        
        with self.lock:
            self.jobs[job_id] = {
                'job_id': job_id,
                'urls': urls,
                'total': len(urls),
                'completed': 0,
                'successful': 0,
                'failed': 0,
                'current_url': None,
                'status': 'queued',  # queued, processing, completed, failed
                'results': [],
                'errors': [],
                'started_at': datetime.now().isoformat(),
                'completed_at': None,
                'generate_observations': generate_observations
            }
        
        # Start processing in background thread
        thread = threading.Thread(target=self._process_job, args=(job_id,), daemon=True)
        thread.start()
        
        return job_id
    
    def _process_job(self, job_id: str):
        """Process URLs in a job sequentially."""
        with self.lock:
            if job_id not in self.jobs:
                return
            job = self.jobs[job_id]
            job['status'] = 'processing'
        
        urls = job['urls']
        generate_observations = job.get('generate_observations', False)
        
        for idx, url in enumerate(urls, 1):
            try:
                # Update current URL being processed
                with self.lock:
                    job['current_url'] = url
                    job['completed'] = idx - 1
                
                print(f"[Job {job_id}] Processing {idx}/{len(urls)}: {url}")
                
                # Run diagnosis
                result = diagnose_site(url)
                
                # Generate technical observation if requested and vulnerabilities detected
                if generate_observations and result.get("vulnerability_detected", False):
                    try:
                        observation = generate_technical_observation(result)
                        if observation:
                            result["technical_observation"] = observation
                    except Exception as e:
                        print(f"Observation generation failed for {url}: {str(e)}")
                
                # Save to file
                parsed = urlparse(url)
                domain = parsed.netloc or parsed.path.split('/')[0]
                domain = domain.replace('www.', '').replace('.', '_').replace('/', '_').replace(':', '_')
                domain = ''.join(c if c.isalnum() or c in ('_', '-') else '_' for c in domain)
                domain = domain[:50]
                filename = f"diagnosis_{domain}.json"
                filepath = os.path.join('results', filename)
                os.makedirs('results', exist_ok=True)
                
                try:
                    with open(filepath, 'w') as f:
                        json.dump(result, f, indent=2)
                    result['output_file'] = filename
                    result['saved'] = True
                except Exception as e:
                    print(f"Failed to save result for {url}: {str(e)}")
                    result['saved'] = False
                    result['save_error'] = str(e)
                
                # Add to results
                with self.lock:
                    job['results'].append({
                        'url': url,
                        'status': 'success',
                        'result': result
                    })
                    job['successful'] += 1
                    job['completed'] = idx
                
            except Exception as e:
                # Handle error gracefully - continue with next URL
                error_msg = str(e)
                print(f"[Job {job_id}] Error processing {url}: {error_msg}")
                
                with self.lock:
                    job['results'].append({
                        'url': url,
                        'status': 'error',
                        'error': error_msg
                    })
                    job['failed'] += 1
                    job['completed'] = idx
                    job['errors'].append({
                        'url': url,
                        'error': error_msg
                    })
        
        # Mark job as completed
        with self.lock:
            job['status'] = 'completed'
            job['completed_at'] = datetime.now().isoformat()
            job['current_url'] = None
        
        print(f"[Job {job_id}] Completed: {job['successful']} successful, {job['failed']} failed")
    
    def get_job_status(self, job_id: str) -> Optional[Dict]:
        """
        Get current status of a job.
        
        Args:
            job_id: Job ID to check
        
        Returns:
            Job status dictionary or None if not found
        """
        with self.lock:
            return self.jobs.get(job_id)
    
    def cleanup_old_jobs(self, max_age_hours: int = 24):
        """Clean up jobs older than specified hours."""
        current_time = datetime.now()
        
        with self.lock:
            jobs_to_remove = []
            for job_id, job in self.jobs.items():
                if job['status'] == 'completed':
                    completed_at = datetime.fromisoformat(job['completed_at'])
                    age_hours = (current_time - completed_at).total_seconds() / 3600
                    if age_hours > max_age_hours:
                        jobs_to_remove.append(job_id)
            
            for job_id in jobs_to_remove:
                del self.jobs[job_id]
        
        if jobs_to_remove:
            print(f"Cleaned up {len(jobs_to_remove)} old jobs")


# Global instance
bulk_processor = BulkProcessor()

