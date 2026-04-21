"""
Classes to load and prepare technology fingerprints.

This module is an implementation detail and is not considered public API.
"""

import sre_compile
import re
import logging
from typing import Optional, Optional, Union, Mapping, Dict, List, Any

logger = logging.getLogger(name="python-Wappalyzer")

# Matches a CSS attribute selector value: [attr*='value'] or [attr="value"] etc.
_CSS_ATTR_VALUE_RE = re.compile(r"(\[[\w:-]+(?:[*~|^$])?=)(['\"])(.*?)(\2\s*\])")
# Characters that are regex-specific and never valid inside a plain CSS attribute value
_CSS_REGEX_CHARS_RE = re.compile(r"[()[\]{}?+*\\]")


class Pattern:
    def __init__(
        self,
        string: str,
        regex: Optional["re.Pattern"] = None,
        version: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> None:
        self.string: str = string
        self.regex: "re.Pattern" = regex or sre_compile.compile("", 0)
        self.version: Optional[str] = version
        self.confidence: int = int(confidence) if confidence else 100


class DomSelector:
    def __init__(
        self,
        selector: str,
        exists: Optional[bool] = None,
        text: Optional[List["Pattern"]] = None,
        attributes: Optional[Mapping[str, List["Pattern"]]] = None,
    ) -> None:
        self.selector: str = selector
        self.exists: bool = bool(exists)
        self.text: Optional[List["Pattern"]] = text
        self.attributes: Optional[Mapping[str, List["Pattern"]]] = attributes
        # self.properties Not supported


class Category:
    def __init__(
        self,
        name: str,
        groups: Optional[List[int]] = None,
        priority: Optional[int] = None,
    ) -> None:
        self.name: str = name
        self.groups: List[int] = groups or []
        self.priority: int = priority or 0


class Technology:
    """
    A detected technology (not implied).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.confidence: Dict[str, int] = {}
        self.versions: List[str] = []

    @property
    def confidenceTotal(self) -> int:
        total = 0
        for v in self.confidence.values():
            total += v
        return total


# Prepare patterns for fields (TODO):
# - "scriptSrc": "regex string"
# - "js": dict string contains ins file to string (with version extraction).
# - "requires" / "excludes" rules/
# - "text" field.


# Inspired by projectdiscovery/wappalyzergo (MIT License)
class Fingerprint:
    """
    A Fingerprint represent a single piece of information about a tech.
    Validated, normalized and regex expressions complied.

    See https://github.com/AliasIO/wappalyzer#json-fields
    """

    def __init__(self, name: str, **attrs: Any) -> None:
        # Required infos
        self.name: str = name

        # Metadata
        self.website: str = attrs.get("website", "??")
        self.cats: List[int] = attrs.get("cats", [])
        self.description: Optional[str] = attrs.get("description")  # type:ignore
        self.icon: Optional[str] = attrs.get("icon")  # type:ignore
        self.cpe: Optional[str] = attrs.get("cpe")  # type:ignore
        self.saas: Optional[bool] = attrs.get("saas")  # type:ignore
        self.oss: Optional[bool] = attrs.get("oss")  # type:ignore
        self.pricing: List[str] = (
            self._prepare_list(attrs["princing"]) if "princing" in attrs else []
        )

        # Implies and cie
        self.implies: List[str] = (
            self._prepare_list(attrs["implies"]) if "implies" in attrs else []
        )
        # self.requires: List[str] = self._prepare_list(attrs['requires']) if 'requires' in attrs else [] # Not supported
        # self.requiresCategory: List[str] = self._prepare_list(attrs['requiresCategory']) if 'requiresCategory' in attrs else [] # Not supported
        # self.excludes: List[str] = self._prepare_list(attrs['excludes']) if 'excludes' in attrs else [] # Not supported

        # Patterns
        self.dom: List[DomSelector] = (
            self._prepare_dom(attrs["dom"]) if "dom" in attrs else []
        )

        self.headers: Mapping[str, List[Pattern]] = (
            self._prepare_headers(attrs["headers"]) if "headers" in attrs else {}
        )
        self.meta: Mapping[str, List[Pattern]] = (
            self._prepare_meta(attrs["meta"]) if "meta" in attrs else {}
        )

        self.html: List[Pattern] = (
            self._prepare_pattern(attrs["html"]) if "html" in attrs else []
        )
        self.text: List[Pattern] = (
            self._prepare_pattern(attrs["text"]) if "text" in attrs else []
        )
        self.url: List[Pattern] = (
            self._prepare_pattern(attrs["url"]) if "url" in attrs else []
        )
        self.scriptSrc: List[Pattern] = (
            self._prepare_pattern(attrs["scriptSrc"]) if "scriptSrc" in attrs else []
        )
        self.scripts: List[Pattern] = (
            self._prepare_pattern(attrs["scripts"]) if "scripts" in attrs else []
        )

        # self.cookies: Mapping[str, List[Pattern]] Not supported
        # self.dns: Mapping[str, List[Pattern]] Not supported
        # self.js: Mapping[str, List[Pattern]] Not supported
        # self.css: List[Pattern] Not supported (yet)
        # self.robots: List[Pattern] Not supported (yet)
        # self.xhr: List[Pattern] Not supported

    @classmethod
    def _prepare_list(cls, thing: Any) -> List[Any]:
        if not isinstance(thing, list):
            return [thing]
        else:
            return thing

    @classmethod
    def _prepare_pattern(cls, pattern: Union[str, List[str]]) -> List[Pattern]:
        """
        Prepare regular expression patterns.
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """
        pattern_objects = []
        if isinstance(pattern, list):
            for p in pattern:
                pattern_objects.extend(cls._prepare_pattern(p))
        else:
            attrs = {}
            patterns = pattern.split("\\;")
            for index, expression in enumerate(patterns):
                if index == 0:
                    attrs["string"] = expression
                    try:
                        attrs["regex"] = re.compile(expression, re.I)  # type: ignore
                    except re.error as err:
                        # Wappalyzer is a JavaScript application therefore some of the regex wont compile in Python.
                        logger.debug(
                            "Caught '{error}' compiling regex: {regex}".format(
                                error=err, regex=patterns
                            )
                        )
                        # regex that never matches:
                        # http://stackoverflow.com/a/1845097/413622
                        attrs["regex"] = re.compile(r"(?!x)x")  # type: ignore
                else:
                    attr = expression.split(":")
                    if len(attr) > 1:
                        key = attr.pop(0)
                        # This adds pattern['version'] when specified with "\\;version:\\1"
                        attrs[str(key)] = ":".join(attr)
            pattern_objects.append(Pattern(**attrs))  # type: ignore

        return pattern_objects

    @classmethod
    def _prepare_pattern_dict(
        cls, thing: Dict[str, Union[str, List[str]]]
    ) -> Mapping[str, List[Pattern]]:
        for k in thing:
            thing[k] = cls._prepare_pattern(thing[k])  # type: ignore
        return thing  # type: ignore

    @classmethod
    def _prepare_meta(
        cls, thing: Union[str, List[str], Dict[str, Union[str, List[str]]]]
    ) -> Mapping[str, List[Pattern]]:
        # Ensure dict
        if not isinstance(thing, dict):
            thing = {"generator": thing}
        # Enure lowercase keys
        return cls._prepare_pattern_dict({k.lower(): v for k, v in thing.items()})

    @classmethod
    def _prepare_headers(
        cls, thing: Dict[str, Union[str, List[str]]]
    ) -> Mapping[str, List[Pattern]]:
        # Enure lowercase keys
        return cls._prepare_pattern_dict({k.lower(): v for k, v in thing.items()})

    @classmethod
    def _sanitize_dom_selector(cls, selector: str) -> Optional[str]:
        """
        Strip Wappalyzer version-extraction regex syntax from a CSS selector.

        Wappalyzer embeds regex patterns inside CSS attribute values
        (e.g. ``[href*='...?ver=([\\d\\.]+))?\\;version:\\1']``).
        The ``\\;version:\\1`` metadata sits INSIDE the attribute value, between
        the regex part and the closing ``']``.  A naïve ``split('\\;')[0]``
        therefore produces an *unclosed* attribute value such as:
        ``link[href*='/path?ver=([\\d\\.]+))?``
        which causes soupsieve's pure-Python CSS parser to hang in a tight GIL-
        holding loop that thread timeouts cannot interrupt.

        This method:
        1. Splits off the ``\\;...`` Wappalyzer suffix.
        2. Detects and closes any unclosed CSS attribute value (odd number of
           quote characters → the closing quote+bracket ended up in the suffix).
        3. Strips regex metacharacters from inside CSS attribute value strings.
        """
        # Step 1: remove Wappalyzer's \\;key:value extraction suffix
        selector = selector.split("\\;")[0].strip()
        if not selector:
            return None

        # Step 2: close any unclosed CSS attribute value.
        # If an odd number of single (or double) quotes remain, the closing
        # quote and bracket were chopped off by the split above.
        if selector.count("'") % 2 == 1:
            selector = selector + "']"
        elif selector.count('"') % 2 == 1:
            selector = selector + '"]'

        # Step 3: strip regex metacharacters from inside CSS attribute values.
        def _clean_attr_value(m: re.Match) -> str:
            attr_op = m.group(1)  # e.g. '[href*='
            quote = m.group(2)  # ' or "
            value = m.group(3)  # the attribute value string
            closing = m.group(4)  # e.g. "']"

            hit = _CSS_REGEX_CHARS_RE.search(value)
            if hit:
                value = value[: hit.start()]
            if not value:
                # Degrade to a plain existence check: [attrname]
                attr_name = re.match(r"\[([\w:-]+)", attr_op)
                return f"[{attr_name.group(1)}]" if attr_name else ""
            return f"{attr_op}{quote}{value}{closing}"

        cleaned = _CSS_ATTR_VALUE_RE.sub(_clean_attr_value, selector).strip()
        return cleaned if cleaned else None

    @classmethod
    def _prepare_dom(
        cls, thing: Union[str, List[str], Dict[str, Dict[str, Union[str, List[str]]]]]
    ) -> List[DomSelector]:
        selectors = []
        if isinstance(thing, str):
            clean = cls._sanitize_dom_selector(thing)
            if clean:
                selectors.append(DomSelector(clean, exists=True))
        elif isinstance(thing, list):
            for _o in thing:
                clean = cls._sanitize_dom_selector(_o)
                if clean:
                    selectors.append(DomSelector(clean, exists=True))
        elif isinstance(thing, dict):
            for cssselect, clause in thing.items():
                clean = cls._sanitize_dom_selector(cssselect)
                if not clean:
                    continue
                # prepare regexes
                _prep_text_patterns = None
                _prep_attr_patterns = None
                _exists = None
                if clause.get("exists") is not None:
                    _exists = True
                if clause.get("text"):
                    _prep_text_patterns = cls._prepare_pattern(clause["text"])
                if clause.get("attributes"):
                    _prep_attr_patterns = {}
                    for _key, pattern in clause["attributes"].items():  # type: ignore
                        _prep_attr_patterns[_key] = cls._prepare_pattern(pattern)
                selectors.append(
                    DomSelector(
                        clean,
                        exists=_exists,
                        text=_prep_text_patterns,
                        attributes=_prep_attr_patterns,
                    )
                )
        return selectors
