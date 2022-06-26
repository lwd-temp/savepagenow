import logging
import typing
from urllib.parse import urljoin

import click
import requests
from requests.utils import parse_header_links

from .exceptions import (
    BadGateway,
    BlockedByRobots,
    CachedPage,
    Forbidden,
    TooManyRequests,
    UnknownError,
    WaybackRuntimeError,
)


logger = logging.getLogger(__name__)


def capture(
    target_url: str,
    user_agent: typing.Optional[str] = "savepagenow (https://github.com/pastpages/savepagenow)",
    accept_cache: bool = False,
    access_key: typing.Optional[str] = None,
    access_secret: typing.Optional[str] = None
):
    """
    Archive the provided URL using archive.org's Wayback Machine.

    Returns the archive.org URL where the capture is stored.

    Raises a CachedPage exception if archive.org declines to conduct a new
    capture and returns a previous snapshot instead.

    To silence that exception, pass into True to the ``accept_cache`` keyword
    argument.
    """
    # If this is an authenticated request ...
    if access_key and access_secret:
        logger.debug("Making authenticated request")
        return _authenticated_request(target_url, user_agent, access_key, access_secret)
    # If this is an anonymous request ...
    elif not access_key and not access_secret:
        logger.debug("Making anonymous request")
        return _anonymous_request(target_url, user_agent, accept_cache)
    else:
        raise ValueError("You must provided both an access key and a secret key to authenticate.")


def capture_or_cache(
    target_url: str,
    user_agent: typing.Optional[str] = "savepagenow (https://github.com/pastpages/savepagenow)",
    access_key: typing.Optional[str] = None,
    access_secret: typing.Optional[str] = None
):
    """
    Archive the provided URL using archive.org's Wayback Machine, unless the page has been recently captured.

    Returns a tuple with the archive.org URL where the capture is stored,
    along with a boolean indicating if a new capture was conducted.

    If the boolean is True, archive.org conducted a new capture. If it is False,
    archive.org has returned a recently cached capture instead, likely taken
    in the previous minutes.
    """
    try:
        return capture(target_url, user_agent=user_agent, accept_cache=False, access_key=access_key, access_secret=access_secret), True
    except CachedPage:
        return capture(target_url, user_agent=user_agent, accept_cache=True, access_key=access_key, access_secret=access_secret), False


@click.command()
@click.argument("url")
@click.option("-ua", "--user-agent", help="User-Agent header for the web request")
@click.option("-c", "--accept-cache", help="Accept and return cached URL", is_flag=True)
@click.option("-ak","--access-key", help="An Internet Archive access key", default=None)
@click.option("-as", "--access-secret", help="An Internet Archive secret key", default=None)
def cli(
    url: str,
    user_agent: typing.Optional[str] = None,
    accept_cache: bool = False,
    access_key: typing.Optional[str] = None,
    access_secret: typing.Optional[str] = None,
):
    """
    Archive the provided URL using archive.org's Wayback Machine.

    Raises a CachedPage exception if archive.org declines to conduct a new capture and returns a previous snapshot instead.
    """
    kwargs: typing.Dict[typing.Any, typing.Any] = {}
    if user_agent:
        kwargs["user_agent"] = user_agent
    if accept_cache:
        kwargs["accept_cache"] = accept_cache
    if (access_key and not access_secret) or (access_secret and not access_key):
        raise ValueError("You must provided both an access key and a secret key to authenticate.")
    if access_key and access_secret:
        kwargs['access_key'] = access_key
        kwargs['access_secret'] = access_secret
    archive_url = capture(url, **kwargs)
    click.echo(archive_url)


def _authenticated_request(target_url, user_agent, access_key, access_secret):
    save_url = "https://web.archive.org/save"
    headers = {
        # "Accept": "application/json",
        "User-Agent": user_agent,
    }
    json = {
        "Authorization": f"LOW {access_key}:{access_secret}",
    }
    data = {
        "url": target_url
    }
    r = requests.post(save_url, data=data, headers=headers, json=json)
    return r.text


def _anonymous_request(target_url, user_agent, accept_cache):
    # Put together the URL that will save our request
    domain = "https://web.archive.org"
    save_url = urljoin(domain, "/save/")
    request_url = save_url + target_url

    headers = {
        "User-Agent": user_agent,
    }
    response = requests.get(request_url, headers=headers)

    # If it has an error header, raise that.
    has_error_header = "X-Archive-Wayback-Runtime-Error" in response.headers
    if has_error_header:
        error_header = response.headers["X-Archive-Wayback-Runtime-Error"]
        if error_header == "RobotAccessControlException: Blocked By Robots":
            raise BlockedByRobots("archive.org returned blocked by robots.txt error")
        else:
            raise WaybackRuntimeError(error_header)

    # If it has an error code, raise that
    status_code = response.status_code
    if status_code == 403:
        raise Forbidden(response.headers)
    elif status_code == 429:
        raise TooManyRequests(response.headers)
    elif status_code == 502:
        raise BadGateway(response.headers)
    elif status_code == 520:
        raise UnknownError(response.headers)

    # If there's a content-location header in the response, we will use that.
    try:
        content_location = response.headers["Content-Location"]
        archive_url = domain + content_location
    except KeyError:
        # If there's not, we  will try to parse out a Link header, which is another style they use.
        try:
            # Parse the Link tag in the header, which points to memento URLs in Wayback
            header_links = parse_header_links(response.headers["Link"])
            archive_obj = [h for h in header_links if h["rel"] == "memento"][0]
            archive_url = archive_obj["url"]
        except Exception:
            # If neither of those things works throw this error.
            raise WaybackRuntimeError(
                dict(status_code=response.status_code, headers=response.headers)
            )

    # Determine if the response was cached
    cached = (
        "X-Page-Cache" in response.headers and response.headers["X-Page-Cache"] == "HIT"
    )

    # If it was cached ...
    if cached:
        # .. and we're not allowing that
        if not accept_cache:
            # ... throw an error
            msg = f"archive.org returned a cache of this page: {archive_url}"
            raise CachedPage(msg)

    # Finally, return the archived URL
    return archive_url


if __name__ == "__main__":
    cli()  # type: ignore
