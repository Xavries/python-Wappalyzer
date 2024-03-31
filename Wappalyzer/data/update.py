import requests
import json
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor

WappalyzerRoot = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"

def fetch_technologies(files: List[str]) -> Dict[str, Dict]:
    """
    Fetches technology data files in parallel and returns a compiled dictionary of technologies.
    
    Args:
        files (List[str]): List of file names to fetch.
    
    Returns:
        Dict[str, Dict]: Compiled dictionary of technologies.
    """
    technologies = {}

    def fetch_file(f: str) -> None:
        """
        Fetches a single technology file and updates the shared dictionary.

        Args:
            f (str): The file name to fetch.
        """
        url = f"{WappalyzerRoot}/technologies/{f}.json"
        try:
            resp = requests.get(url)
            resp.raise_for_status()
            m = resp.json()
            technologies.update(m)
        except Exception as e:
            print(f"Failed to download or parse {f}.json: {e}")

    with ThreadPoolExecutor() as executor:
        executor.map(fetch_file, files)
    
    return technologies

def fetch_categories() -> Dict[str, Dict]:
    """
    Fetches and decodes category data into a dictionary.

    Returns:
        Dict[str, Dict]: Dictionary of categories.
    """
    url = f"{WappalyzerRoot}/categories.json"
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        categories = resp.json()
    except Exception as e:
        print(f"Failed to download or parse categories.json: {e}")
        return {}
    return categories

def get_technology_data() -> Dict[str, Dict]:
    """
    Gets and Compiles categories and technologies into a single dictionary structure.

    Returns:
        Dict[str, Dict]: Compiled technology data.
    """
    categories = fetch_categories()
    files = ["_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
    technologies = fetch_technologies(files)

    technology_data = {"technologies": technologies, "categories": categories}

    return technology_data

if __name__ == "__main__":

    # Example usage:
    technology_data = get_technology_data()
    print(json.dumps(technology_data, indent=2))  # For demonstration; replace with desired use.
