from typing import Callable, Dict, Iterable, List, Any, Mapping, Set
import json
import logging
import pkg_resources
import re
import os
import pathlib
import signal

from typing import Optional

from Wappalyzer.fingerprint import Fingerprint, Pattern, Technology, Category
from Wappalyzer.data.update import get_technology_data
from Wappalyzer.webpage import WebPage, IWebPage

logger = logging.getLogger(name="python-Wappalyzer")


class WappalyzerError(Exception):
    # unused for now
    """
    Raised for fatal Wappalyzer errors.
    """
    pass


class Wappalyzer:
    """
    Python Wappalyzer driver.

    Consider the following exemples.

    Here is how you can use the latest technologies file from AliasIO/wappalyzer repository.

    .. python::

        from Wappalyzer import Wappalyzer
        wappalyzer=Wappalyzer.latest(update=True)
        # Create webpage
        webpage=WebPage.new_from_url('http://example.com')
        # analyze
        results = wappalyzer.analyze_with_categories(webpage)


    Here is how you can custom request and headers arguments:

    .. python::

        import requests
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('http://exemple.com', headers={'User-Agent': 'Custom user agent'})
        wappalyzer.analyze_with_categories(webpage)

    """

    def __init__(self, categories: Dict[str, Any], technologies: Dict[str, Any]):
        """
        Manually initialize a new Wappalyzer instance.

        You might want to use the factory method: `latest`

        :param categories: Map of category ids to names, as in ``technologies.json``.
        :param technologies: Map of technology names to technology dicts, as in ``technologies.json``.
        """
        self.categories: Mapping[str, Category] = {
            k: Category(**v) for k, v in categories.items()
        }
        self.technologies: Mapping[str, Fingerprint] = {
            k: Fingerprint(name=k, **v) for k, v in technologies.items()
        }
        self.detected_technologies: Dict[str, Dict[str, Technology]] = {}

        self._confidence_regexp = re.compile(r"(.+)\\;confidence:(\d+)")

    @classmethod
    def latest(
        cls, technologies_file: str = None, update: bool = False
    ) -> "Wappalyzer":
        """
        Construct a Wappalyzer instance.

        Use ``update=True`` to download the very latest file from internet.
        Do not update if the file has already been updated in the last 24 hours.
        *New in version 0.4.0*

        Use ``technologies_file=/some/path/technologies.json`` to load a
        custom technologies file.

        If no arguments is passed, load the default ``data/technologies.json`` file
        inside the package ressource.

        :param technologies_file: File path
        :param update: Download and use the latest ``technologies.json`` file
            from `AliasIO/wappalyzer <https://github.com/AliasIO/wappalyzer>`_ repository.
        """
        default = pkg_resources.resource_string(__name__, "data/technologies.json")

        if technologies_file:
            with open(technologies_file, "r", encoding="utf-8") as fd:
                lastest_technologies_file_dict = json.load(fd)
            logger.debug(
                "Using local technologies.json file at {}".format(technologies_file)
            )
        elif update:
            _technologies_file: pathlib.Path

            # Get the lastest file
            try:
                lastest_technologies_file_dict = get_technology_data()
                _technologies_file = pathlib.Path(
                    cls._find_files(
                        [
                            "HOME",
                            "APPDATA",
                        ],
                        [".python-Wappalyzer/technologies.json"],
                        create=True,
                    ).pop()
                )
                logger.debug("python-Wappalyzer technologies.json data loaded")
                with _technologies_file.open("w", encoding="utf-8") as tfile:
                    json.dump(lastest_technologies_file_dict, tfile)
                    logger.info("python-Wappalyzer technologies.json file updated")

            except Exception as err:  # Or loads default
                logger.warning(
                    "Could not download latest Wappalyzer technologies.json file because of error : '{}'. Using default. ".format(
                        err
                    )
                )
                lastest_technologies_file_dict = json.loads(default)
            logger.debug(
                "Using technologies.json file at {}".format(
                    _technologies_file.as_posix()
                )
            )
        else:
            lastest_technologies_file_dict = json.loads(default)

        return cls(
            categories=lastest_technologies_file_dict["categories"],
            technologies=lastest_technologies_file_dict["technologies"],
        )

    @staticmethod
    def _find_files(
        env_location: List[str],
        potential_files: List[str],
        default_content: str = "",
        create: bool = False,
    ) -> List[str]:
        """Find existent files based on folders name and file names.
        Arguments:
        - `env_location`: list of environment variable to use as a base path. Exemple: ['HOME', 'XDG_CONFIG_HOME', 'APPDATA', 'PWD']
        - `potential_files`: list of filenames. Exemple: ['.myapp/conf.ini',]
        - `default_content`: Write default content if the file does not exist
        - `create`: Create the file in the first existing env_location with default content if the file does not exist
        """
        potential_paths = []
        existent_files = []

        env_loc_exists = False
        # build potential_paths of config file
        for env_var in env_location:
            if env_var in os.environ:
                env_loc_exists = True
                for file_path in potential_files:
                    potential_paths.append(os.path.join(os.environ[env_var], file_path))
        if not env_loc_exists and create:
            raise RuntimeError(f"Cannot find any of the env locations {env_location}. ")
        # If file exist, add to list
        for p in potential_paths:
            if os.path.isfile(p):
                existent_files.append(p)
        # If no file foud and create=True, init new file
        if len(existent_files) == 0 and create:
            os.makedirs(os.path.dirname(potential_paths[0]), exist_ok=True)
            with open(potential_paths[0], "w", encoding="utf-8") as config_file:
                config_file.write(default_content)
            existent_files.append(potential_paths[0])
        return existent_files

    def _has_technology(self, tech_fingerprint: Fingerprint, webpage: IWebPage) -> bool:
        """
        Determine whether the web page matches the technology signature.
        """

        has_tech = False
        # Search the easiest things first and save the full-text search of the
        # HTML for last

        # analyze url patterns
        # print(f"Analyzing URL patterns for technology {tech_fingerprint.name}")
        for pattern in tech_fingerprint.url:
            if pattern.regex.search(webpage.url):
                self._set_detected_app(
                    webpage.url, tech_fingerprint, "url", pattern, value=webpage.url
                )
        # analyze headers patterns
        # print(f"Analyzing headers patterns for technology {tech_fingerprint.name}")
        for name, patterns in list(tech_fingerprint.headers.items()):
            if name in webpage.headers:
                content = webpage.headers[name]
                if len(content) == 0 or len(content) > 10000:
                    continue
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._set_detected_app(
                            webpage.url,
                            tech_fingerprint,
                            "headers",
                            pattern,
                            value=content,
                            key=name,
                        )
                        has_tech = True
        # analyze scripts patterns
        # print(f"Analyzing scripts patterns for technology {tech_fingerprint.name}")
        for pattern in tech_fingerprint.scripts:
            for script in webpage.scripts:
                if len(script) == 0 or len(script) > 10000:
                    continue
                if pattern.regex.search(script):
                    self._set_detected_app(
                        webpage.url, tech_fingerprint, "scripts", pattern, value=script
                    )
                    has_tech = True
        # analyze meta patterns
        # print(f"Analyzing meta patterns for technology {tech_fingerprint.name}")
        for name, patterns in list(tech_fingerprint.meta.items()):
            if name in webpage.meta:
                content = webpage.meta[name]
                if len(content) == 0 or len(content) > 10000:
                    continue
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._set_detected_app(
                            webpage.url,
                            tech_fingerprint,
                            "meta",
                            pattern,
                            value=content,
                            key=name,
                        )
                        has_tech = True
        # analyze html patterns
        # print(f"Analyzing HTML patterns for technology {tech_fingerprint.name}")
        for pattern in tech_fingerprint.html:
            if len(webpage.html) == 0 or len(webpage.html) > 10000:
                continue
            if pattern.regex.search(webpage.html):
                self._set_detected_app(
                    webpage.url, tech_fingerprint, "html", pattern, value=webpage.html
                )
                has_tech = True
        # analyze dom patterns
        # print(f"Analyzing DOM patterns for technology {tech_fingerprint.name}")
        # css selector, list of css selectors, or dict from css selector to dict with some of keys:
        #           - "exists": "": only check if the selector matches somthing, equivalent to the list form.
        #           - "text": "regex": check if the .innerText property of the element that matches the css selector matches the regex (with version extraction).
        #           - "attributes": {dict from attr name to regex}: check if the attribute value of the element that matches the css selector matches the regex (with version extraction).
        # analyze dom patterns signal
        selector_unique_check_set = list()
        try:
            for idx, selector in enumerate(tech_fingerprint.dom):
                print(
                    f"Processing DOM selector {idx+1}/{len(tech_fingerprint.dom)}: {selector.selector[:100]}"
                )

                try:
                    # Add timeout for select operation
                    def timeout_handler(signum, frame):
                        raise TimeoutError("Selector search timed out")

                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(5)  # 5 second timeout for selector

                    try:
                        items = list(webpage.select(selector.selector))
                        signal.alarm(0)  # Cancel alarm
                    except TimeoutError:
                        signal.alarm(0)
                        print(f"⚠️  Timeout on selector: {selector.selector[:100]}")
                        continue
                    except Exception as e:
                        signal.alarm(0)
                        print(f"Error selecting elements: {e}")
                        continue

                    print(
                        f"Found {len(items)} elements for selector: {selector.selector[:100]}"
                    )

                    for item_idx, item in enumerate(items):
                        if item_idx > 100:  # Limit number of items processed
                            print(f"Skipping remaining items (processed 100)")
                            break

                        inner_html_len = len(item.inner_html)
                        print(
                            f"Processing item {item_idx+1}/{len(items)} with inner_html length {inner_html_len}"
                        )

                        if selector.exists:
                            self._set_detected_app(
                                webpage.url,
                                tech_fingerprint,
                                "dom",
                                Pattern(string=selector.selector),
                                value="",
                            )
                            has_tech = True
                        if selector.text:
                            for pattern in selector.text:
                                if inner_html_len == 0 or inner_html_len > 10000:
                                    continue
                                # print(
                                #     f"selector.text pattern: {pattern.regex}. item.inner_html = {item.inner_html[:100]}"
                                # )

                                # Check if pattern is simple (anchored exact match)
                                pattern_str = pattern.regex.pattern
                                is_anchored = pattern_str.startswith(
                                    "^"
                                ) and pattern_str.endswith("$")

                                if is_anchored:
                                    # For anchored patterns like ^Pleroma$, use simple string comparison
                                    search_str = pattern_str[1:-1]  # Remove ^ and $
                                    # print(
                                    #     f"Using simple string comparison for anchored pattern: {search_str}"
                                    # )

                                    # Check case-insensitive if IGNORECASE flag is set
                                    match = (
                                        item.inner_html.strip().lower()
                                        == search_str.lower()
                                    )

                                    if match:
                                        # print(f"Match found with simple comparison")
                                        self._set_detected_app(
                                            webpage.url,
                                            tech_fingerprint,
                                            "dom",
                                            pattern,
                                            value=item.inner_html,
                                        )
                                        has_tech = True
                                    # else:
                                    #     print(f"No match found with simple comparison")
                                else:
                                    # For non-anchored patterns, use regex
                                    # print(
                                    #     f"Using regex search for pattern: {pattern_str[:50]}"
                                    # )
                                    try:
                                        if pattern.regex.search(item.inner_html):
                                            self._set_detected_app(
                                                webpage.url,
                                                tech_fingerprint,
                                                "dom",
                                                pattern,
                                                value=item.inner_html,
                                            )
                                            has_tech = True
                                    except Exception as e:
                                        print(f"Error in regex search: {e}")
                        if selector.attributes:
                            # print(
                            #     f"Analyzing attributes for selector {selector.selector[:50]}"
                            # )
                            for attrname, patterns in list(selector.attributes.items()):
                                check_str = f"{selector.text} {attrname} {[str(i.regex) for i in patterns]}"
                                if check_str in selector_unique_check_set:
                                    continue
                                # print(
                                #     f"selector_unique_check_set length: {len(selector_unique_check_set)}"
                                # )
                                selector_unique_check_set.append(check_str)
                                # print(f"checking attribute {attrname} for patterns {check_str[:100]}")
                                _content = item.attributes.get(attrname)
                                if _content and len(_content) < 10000:
                                    # if not isinstance(_content, str):
                                    #     print("_content", _content)
                                    _content = (
                                        " ".join(_content)
                                        if isinstance(_content, list)
                                        else _content
                                    )
                                    if "video" in _content:
                                        print(
                                            f"skipping video content {_content[:100]}"
                                        )
                                        continue
                                    for pattern in patterns:
                                        # print(f"checking pattern {pattern.regex} for content {_content[:100]}")
                                        try:
                                            if pattern.regex.search(_content):
                                                self._set_detected_app(
                                                    webpage.url,
                                                    tech_fingerprint,
                                                    "dom",
                                                    pattern,
                                                    value=_content,
                                                )
                                                has_tech = True
                                        except Exception as e:
                                            print(
                                                f"Error in attribute regex search: {e}"
                                            )
                except Exception as e:
                    print(f"Error processing selector {selector.selector[:100]}: {e}")
                    continue
        except Exception as e:
            print(f"Error in DOM analysis: {e}")

        # print(f"has_tech: {has_tech} for technology {tech_fingerprint.name}")
        return has_tech

    def _set_detected_app(
        self,
        url: str,
        tech_fingerprint: Fingerprint,
        app_type: str,
        pattern: Pattern,
        value: str,
        key="",
    ) -> None:
        """
        Store detected technology to the detected_technologies dict.
        """
        # Lookup Technology object in the cache
        if url not in self.detected_technologies:
            self.detected_technologies[url] = {}
        if tech_fingerprint.name not in self.detected_technologies[url]:
            self.detected_technologies[url][tech_fingerprint.name] = Technology(
                tech_fingerprint.name
            )
        detected_tech = self.detected_technologies[url][tech_fingerprint.name]

        # Set confidence level
        if key != "":
            key += " "
        match_name = app_type + " " + key + pattern.string

        detected_tech.confidence[match_name] = pattern.confidence

        # Dectect version number
        if pattern.version:
            allmatches = re.findall(pattern.regex, value)
            for i, matches in enumerate(allmatches):
                version = pattern.version
                # Check for a string to avoid enumerating the string
                if isinstance(matches, str):
                    matches = [matches]
                for index, match in enumerate(matches):
                    # Parse ternary operator
                    ternary = re.search(
                        re.compile("\\\\" + str(index + 1) + "\\?([^:]+):(.*)$", re.I),
                        version,
                    )
                    if (
                        ternary
                        and len(ternary.groups()) == 2
                        and ternary.group(1) is not None
                        and ternary.group(2) is not None
                    ):
                        version = version.replace(
                            ternary.group(0),
                            ternary.group(1) if match != "" else ternary.group(2),
                        )
                    # Replace back references
                    version = version.replace("\\" + str(index + 1), match)
                if version != "" and version not in detected_tech.versions:
                    detected_tech.versions.append(version)
            self._sort_app_version(detected_tech)

    def _sort_app_version(self, detected_tech: Technology) -> None:
        """
        Sort version number (find the longest version number that *is supposed to* contains all shorter detected version numbers).
        """
        if len(detected_tech.versions) >= 1:
            return
        detected_tech.versions = sorted(
            detected_tech.versions, key=self._cmp_to_key(self._sort_app_versions)
        )

    def _get_implied_technologies(
        self, detected_technologies: Iterable[str]
    ) -> Iterable[str]:
        """
        Get the set of technologies implied by `detected_technologies`.
        """

        def __get_implied_technologies(technologies: Iterable[str]) -> Iterable[str]:
            _implied_technologies = set()
            for tech in technologies:
                try:
                    for implie in self.technologies[tech].implies:
                        # If we have no doubts just add technology
                        if "confidence" not in implie:
                            _implied_technologies.add(implie)

                        # Case when we have "confidence" (some doubts)
                        else:
                            try:
                                # Use more strict regexp (cause we have already checked the entry of "confidence")
                                # Also, better way to compile regexp one time, instead of every time
                                app_name, confidence = self._confidence_regexp.search(implie).groups()  # type: ignore
                                if int(confidence) >= 50:
                                    _implied_technologies.add(app_name)
                            except (ValueError, AttributeError):
                                pass
                except KeyError:
                    pass
            return _implied_technologies

        implied_technologies = __get_implied_technologies(detected_technologies)
        all_implied_technologies: Set[str] = set()

        # Descend recursively until we've found all implied technologies
        while not all_implied_technologies.issuperset(implied_technologies):
            all_implied_technologies.update(implied_technologies)
            implied_technologies = __get_implied_technologies(all_implied_technologies)

        return all_implied_technologies

    def get_categories(self, tech_name: str) -> List[str]:
        """
        Returns a list of the categories for an technology name.

        :param tech_name: Tech name
        """
        cat_nums = (
            self.technologies[tech_name].cats if tech_name in self.technologies else []
        )
        cat_names = [
            self.categories[str(cat_num)].name
            for cat_num in cat_nums
            if str(cat_num) in self.categories
        ]
        return cat_names

    def get_versions(self, url: str, app_name: str) -> List[str]:
        """
        Retuns a list of the discovered versions for an app name.

        :param url: URL of the webpage
        :param app_name: App name
        """
        try:
            return self.detected_technologies[url][app_name].versions
        except KeyError:
            return []

    def get_confidence(self, url: str, app_name: str) -> Optional[int]:
        """
        Returns the total confidence for an app name.

        :param url: URL of the webpage
        :param app_name: App name
        """
        try:
            return self.detected_technologies[url][app_name].confidenceTotal
        except KeyError:
            return None

    def analyze(self, webpage: IWebPage) -> Set[str]:
        """
        Return a set of technology that can be detected on the web page.

        :param webpage: The Webpage to analyze
        """
        print(f"Analyzing webpage: {webpage.url}")
        detected_technologies = set()

        for tech_name, technology in list(self.technologies.items()):
            if self._has_technology(technology, webpage):
                detected_technologies.add(tech_name)

        print(f"Initially detected technologies: {detected_technologies}")
        detected_technologies.update(
            self._get_implied_technologies(detected_technologies)
        )
        print(f"Initially detected technologies: {detected_technologies}")
        print(f"Total: {len(detected_technologies)} technologies")

        return detected_technologies

    def analyze_with_versions(self, webpage: IWebPage) -> Dict[str, Dict[str, Any]]:
        """
        Return a dict of applications and versions that can be detected on the web page.

        :param webpage: The Webpage to analyze
        """
        detected_apps = self.analyze(webpage)
        versioned_apps = {}

        for app_name in detected_apps:
            versions = self.get_versions(webpage.url, app_name)
            versioned_apps[app_name] = {"versions": versions}

        return versioned_apps

    def analyze_with_categories(self, webpage: IWebPage) -> Dict[str, Dict[str, Any]]:
        """
        Return a dict of technologies and categories that can be detected on the web page.

        :param webpage: The Webpage to analyze

        >>> wappalyzer.analyze_with_categories(webpage)
        {'Amazon ECS': {'categories': ['IaaS']},
        'Amazon Web Services': {'categories': ['PaaS']},
        'Azure CDN': {'categories': ['CDN']},
        'Docker': {'categories': ['Containers']}}

        """
        detected_technologies = self.analyze(webpage)
        categorised_technologies = {}

        for tech_name in detected_technologies:
            cat_names = self.get_categories(tech_name)
            categorised_technologies[tech_name] = {"categories": cat_names}

        return categorised_technologies

    def analyze_with_versions_and_categories(
        self, webpage: IWebPage
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return a dict of applications and versions and categories that can be detected on the web page.

        :param webpage: The Webpage to analyze

        >>> wappalyzer.analyze_with_versions_and_categories(webpage)
        {'Font Awesome': {'categories': ['Font scripts'], 'versions': ['5.4.2']},
        'Google Font API': {'categories': ['Font scripts'], 'versions': []},
        'MySQL': {'categories': ['Databases'], 'versions': []},
        'Nginx': {'categories': ['Web servers', 'Reverse proxies'], 'versions': []},
        'PHP': {'categories': ['Programming languages'], 'versions': ['5.6.40']},
        'WordPress': {'categories': ['CMS', 'Blogs'], 'versions': ['5.4.2']},
        'Yoast SEO': {'categories': ['SEO'], 'versions': ['14.6.1']}}

        """
        versioned_apps = self.analyze_with_versions(webpage)
        versioned_and_categorised_apps = versioned_apps

        for app_name in versioned_apps:
            cat_names = self.get_categories(app_name)
            versioned_and_categorised_apps[app_name]["categories"] = cat_names

        return versioned_and_categorised_apps

    def _sort_app_versions(self, version_a: str, version_b: str) -> int:
        return len(version_a) - len(version_b)

    def _cmp_to_key(self, mycmp: Callable[..., Any]):
        """
        Convert a cmp= function into a key= function
        """

        # https://docs.python.org/3/howto/sorting.html
        class CmpToKey:
            def __init__(self, obj, *args):
                self.obj = obj

            def __lt__(self, other):
                return mycmp(self.obj, other.obj) < 0

            def __gt__(self, other):
                return mycmp(self.obj, other.obj) > 0

            def __eq__(self, other):
                return mycmp(self.obj, other.obj) == 0

            def __le__(self, other):
                return mycmp(self.obj, other.obj) <= 0

            def __ge__(self, other):
                return mycmp(self.obj, other.obj) >= 0

            def __ne__(self, other):
                return mycmp(self.obj, other.obj) != 0

        return CmpToKey


def analyze(
    url: str,
    update: bool = False,
    useragent: str = None,
    timeout: int = 10,
    verify: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Quick utility method to analyze a website with minimal configurable options.

    :See: `WebPage` and `Wappalyzer`.

    :Parameters:
        - `url`: URL
        - `update`: Update the technologies file from the internet
        - `useragent`: Request user agent
        - `timeout`: Request timeout
        - `verify`: SSL cert verify

    :Return:
        `dict`. Just as `Wappalyzer.analyze_with_versions_and_categories`.
    :Note: More information might be added to the returned values in the future
    """
    # Create Wappalyzer
    wappalyzer = Wappalyzer.latest(update=update)
    # Create WebPage
    headers = {}
    if useragent:
        headers["User-Agent"] = useragent
    webpage = WebPage.new_from_url(url, headers=headers, timeout=timeout, verify=verify)
    # Analyze
    results = wappalyzer.analyze_with_versions_and_categories(webpage)
    return results
