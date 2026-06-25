"""
Containers for a Web page and it's components.
Wraps only the information strictly necessary to run the Wappalyzer engine.
"""

import abc
import re
from typing import Dict, Iterable, List, Mapping, Any
try:
    from typing import Protocol
except ImportError:
    Protocol = object # type: ignore

import aiohttp
import requests
from requests.structures import CaseInsensitiveDict

def _raise_not_dict(obj:Any, name:str) -> None:
    try:
        list(obj.keys())
    except AttributeError:
        raise ValueError(f"{name} must be a dictionary-like object")

# Split a (possibly comma-merged) Set-Cookie header into individual cookies.
# Only split on a comma that introduces a new "<token>=" cookie, so commas that
# appear inside an Expires date (e.g. "Wed, 09 Jun 2021 ...") are preserved.
_SET_COOKIE_SPLIT_RE = re.compile(r',\s*(?=[^\x00-\x20()<>@,;:\\"/\[\]?={}]+=)')


def _set_cookie_values(headers: Any) -> List[str]:
    """Return every ``Set-Cookie`` header value from a headers mapping.

    Handles multi-valued mappings that keep each header separate (aiohttp's
    ``CIMultiDict``, ``http.client`` messages, urllib3) as well as single-valued
    mappings (plain ``dict``, requests' ``CaseInsensitiveDict``) where multiple
    ``Set-Cookie`` headers have been comma-merged into one string.
    """
    if headers is None:
        return []
    # Multi-valued mappings expose all values for a key via one of these.
    for attr in ("getall", "get_all", "getlist"):
        getter = getattr(headers, attr, None)
        if callable(getter):
            try:
                values = getter("Set-Cookie")
            except TypeError:
                # multidict.getall has no implicit default
                values = getter("Set-Cookie", [])
            except Exception:
                values = None
            if values:
                return list(values)
            break
    # Single-valued mapping: look the header up case-insensitively.
    getter = getattr(headers, "get", None)
    if callable(getter):
        for key in ("Set-Cookie", "set-cookie"):
            try:
                value = getter(key)
            except Exception:
                value = None
            if value:
                return [value] if isinstance(value, str) else list(value)
    return []


def _parse_set_cookie(raw: Any) -> Dict[str, str]:
    """Parse ``Set-Cookie`` header value(s) into a ``{name: value}`` dict.

    ``raw`` may be ``None``, a single header string (which can itself carry
    several comma-merged cookies), or a list of header strings.
    """
    if not raw:
        return {}
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    cookies: Dict[str, str] = {}
    for value in values:
        if not value:
            continue
        for chunk in _SET_COOKIE_SPLIT_RE.split(value):
            # The cookie's name=value pair is everything before the first ';'.
            name_value = chunk.split(";", 1)[0].strip()
            if "=" not in name_value:
                continue
            name, _, val = name_value.partition("=")
            name = name.strip()
            if name:
                cookies[name] = val.strip().strip('"')
    return cookies

class ITag(Protocol):
    """
    A HTML tag, decoupled from any particular HTTP library's API.
    """
    name: str
    attributes: Mapping[str, str]
    inner_html: str

class BaseTag(ITag, abc.ABC):
    """
    Subclasses must implement inner_html().
    """
    def __init__(self, name:str, attributes:Mapping[str, str]) -> None:
        _raise_not_dict(attributes, "attributes")
        self.name = name
        self.attributes = attributes
    @property
    def inner_html(self) -> str: # type: ignore
        """Returns the inner HTML of an element as a UTF-8 encoded bytestring"""
        raise NotImplementedError()

class IWebPage(Protocol):
    """
    Interfacte declaring the required methods/attributes of a WebPage object.

    Simple representation of a web page, decoupled from any particular HTTP library's API.
    """
    url: str
    html: str
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    scripts: List[str]
    meta: Mapping[str, str]
    def select(self, selector:str) -> Iterable[ITag]:
        raise NotImplementedError()

class BaseWebPage(IWebPage):
    """
    Implements factory methods for a WebPage.

    Subclasses must implement _parse_html() and select(string).
    """
    def __init__(self, url:str, html:str, headers:Mapping[str, str],
                 cookies:Mapping[str, str]=None):
        """
        Initialize a new WebPage object manually.

        >>> from Wappalyzer import WebPage
        >>> w = WebPage('exemple.com',  html='<strong>Hello World</strong>', headers={'Server': 'Apache', })

        :param url: The web page URL.
        :param html: The web page content (HTML)
        :param headers: The HTTP response headers
        :param cookies: The HTTP response cookies (name -> value). If omitted,
            they are parsed from the ``Set-Cookie`` header(s) in ``headers``.
        """
        _raise_not_dict(headers, "headers")
        if cookies is not None:
            _raise_not_dict(cookies, "cookies")
        else:
            # Derive cookies from the response's Set-Cookie header(s), correctly
            # handling the case of multiple cookies in one or more headers.
            cookies = _parse_set_cookie(_set_cookie_values(headers))
        self.url = url
        self.html = html
        self.headers = CaseInsensitiveDict(headers)
        self.cookies = CaseInsensitiveDict(cookies)
        self.scripts: List[str] = []
        self.meta: Mapping[str, str] = {}
        self._parse_html()

    def _parse_html(self):
        raise NotImplementedError()
    
    @classmethod
    def new_from_url(cls, url: str, **kwargs:Any) -> IWebPage:
        """
        Constructs a new WebPage object for the URL,
        using the `requests` module to fetch the HTML.

        >>> from Wappalyzer import WebPage
        >>> page = WebPage.new_from_url('exemple.com', timeout=5)

        :param url: URL 
        :param headers: (optional) Dictionary of HTTP Headers to send.
        :param cookies: (optional) Dict or CookieJar object to send.
        :param timeout: (optional) How many seconds to wait for the server to send data before giving up. 
        :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        :param verify: (optional) Boolean, it controls whether we verify the SSL certificate validity. 
        :param **kwargs: Any other arguments are passed to `requests.get` method as well. 
        """
        response = requests.get(url, **kwargs)
        return cls.new_from_response(response)

    @classmethod
    def new_from_response(cls, response:requests.Response) -> IWebPage:
        """
        Constructs a new WebPage object for the response,
        using the `BeautifulSoup` module to parse the HTML.

        :param response: `requests.Response` object
        """
        return cls(response.url, html=response.text, headers=response.headers,
                   cookies=response.cookies.get_dict())


    @classmethod
    async def new_from_url_async(cls, url: str, verify: bool = True,
                                 aiohttp_client_session: aiohttp.ClientSession = None, **kwargs:Any) -> IWebPage:
        """
        Same as new_from_url only Async.

        Constructs a new WebPage object for the URL,
        using the `aiohttp` module to fetch the HTML.

        >>> from Wappalyzer import WebPage
        >>> from aiohttp import ClientSession
        >>> async with ClientSession() as session:
        ...     page = await WebPage.new_from_url_async(aiohttp_client_session=session)
        
        :param url: URL
        :param aiohttp_client_session: `aiohttp.ClientSession` instance to use, optional.
        :param verify: (optional) Boolean, it controls whether we verify the SSL certificate validity. 
        :param headers: Dict. HTTP Headers to send with the request (optional).
        :param cookies: Dict. HTTP Cookies to send with the request (optional).
        :param timeout: Int. override the session's timeout (optional)
        :param proxy: Proxy URL, `str` or `yarl.URL` (optional).
        :param **kwargs: Any other arguments are passed to `aiohttp.ClientSession.get` method as well. 

        """

        if not aiohttp_client_session:
            connector = aiohttp.TCPConnector(ssl=verify)
            aiohttp_client_session = aiohttp.ClientSession(connector=connector)

        async with aiohttp_client_session.get(url, **kwargs) as response:
            return await cls.new_from_response_async(response)

    @classmethod
    async def new_from_response_async(cls, response:aiohttp.ClientResponse) -> IWebPage:
        """
        Constructs a new WebPage object for the response,
        using the `BeautifulSoup` module to parse the HTML.

        >>> from aiohttp import ClientSession
        >>> wappalyzer = Wappalyzer.latest()
        >>> async with ClientSession() as session:
        ...     page = await session.get("http://example.com")
        ...
        >>> webpage = await WebPage.new_from_response_async(page)

        :param response: `aiohttp.ClientResponse` object
        """
        html = await response.text()
        cookies = {name: morsel.value for name, morsel in response.cookies.items()}
        return cls(str(response.url), html=html, headers=response.headers,
                   cookies=cookies)