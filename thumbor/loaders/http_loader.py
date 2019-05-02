#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/thumbor/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2011 globo.com thumbor@googlegroups.com

import datetime
import re
from functools import partial
from os.path import join, exists, abspath
from os import fstat

import cv2

import tornado.httpclient
from six.moves.urllib.parse import quote, unquote, urlparse

from thumbor.loaders import LoaderResult
from thumbor.utils import logger
from tornado.concurrent import return_future


def frame_capture(context, url):
    filename = url.split('/')[-1].split('.')[0] + '.jpg'
    filepath = join(context.config.FILE_STORAGE_ROOT_PATH.rstrip(
        '/'), filename)
    filpath = abspath(filepath)

    vidcap = cv2.VideoCapture(url)
    success, image = vidcap.read()
    count = 0
    while (count < 10):
        success, image = vidcap.read()
        count += 1
    cv2.imwrite(filpath, image)  # save frame as JPEG file
    print('Reading frame', success, url)
    return filepath


def load_file(context, file_path, callback):
    inside_root_path = file_path.startswith(
        abspath(context.config.FILE_LOADER_ROOT_PATH))

    result = LoaderResult()

    if not inside_root_path:
        result.error = LoaderResult.ERROR_NOT_FOUND
        result.successful = False
        callback(result)
        return

    # keep backwards compatibility, try the actual path first
    # if not found, unquote it and try again
    if not exists(file_path):
        file_path = unquote(file_path)

    if exists(file_path):
        with open(file_path, 'r') as f:
            stats = fstat(f.fileno())

            result.successful = True
            result.buffer = f.read()

            result.metadata.update(
                size=stats.st_size,
                updated_at=datetime.datetime.utcfromtimestamp(stats.st_mtime))
    else:
        result.error = LoaderResult.ERROR_NOT_FOUND
        result.successful = False

    callback(result)


def encode_url(url):
    if url == unquote(url):
        return quote(url.encode('utf-8'), safe='~@#$&()*!+=:;,.?/\'')
    else:
        return url


def quote_url(url):
    return encode_url(unquote(url).decode('utf-8'))


def _normalize_url(url):
    url = quote_url(url)
    return url if url.startswith('http') else 'http://%s' % url


def validate(context, url, normalize_url_func=_normalize_url):
    url = normalize_url_func(url)
    res = urlparse(url)

    if not res.hostname:
        return False

    if not context.config.ALLOWED_SOURCES:
        return True

    for pattern in context.config.ALLOWED_SOURCES:
        if isinstance(pattern, re._pattern_type):
            match = url
        else:
            pattern = '^%s$' % pattern
            match = res.hostname

        if re.match(pattern, match):
            return True

    return False


def return_contents(response, url, callback, context, req_start=None):
    if req_start:
        finish = datetime.datetime.now()
        res = urlparse(url)
        context.metrics.timing(
            'original_image.fetch.{0}.{1}'.format(response.code, res.netloc),
            (finish - req_start).total_seconds() * 1000,
        )

    result = LoaderResult()
    context.metrics.incr('original_image.status.' + str(response.code))
    if response.error:
        result.successful = False
        if response.code == 599:
            # Return a Gateway Timeout status downstream if upstream times out
            result.error = LoaderResult.ERROR_TIMEOUT
        else:
            result.error = LoaderResult.ERROR_NOT_FOUND

        logger.warn(u"ERROR retrieving image {0}: {1}".format(
            url, str(response.error)))

    elif response.body is None or len(response.body) == 0:
        result.successful = False
        result.error = LoaderResult.ERROR_UPSTREAM

        logger.warn(u"ERROR retrieving image {0}: Empty response.".format(url))
    else:
        if response.time_info:
            for x in response.time_info:
                context.metrics.timing('original_image.time_info.' + x,
                                       response.time_info[x] * 1000)
            context.metrics.timing(
                'original_image.time_info.bytes_per_second',
                len(response.body) / response.time_info['total'])
        result.buffer = response.body
        result.metadata.update(response.headers)
        context.metrics.incr('original_image.response_bytes', len(
            response.body))

    callback(result)


@return_future
def load(context, url, callback, normalize_url_func=_normalize_url):
    url = normalize_url_func(url)
    is_video = (url.find('unsafe') == -1 or url.find('filters') == -1) and url.find('.mp4') != -1 or \
        url.find('.3gp') != -1 or \
        url.find('.mpg') != -1 or \
        url.find('.MP4') != -1 or \
        url.find('.3GP') != -1 or \
        url.find('.MPG') != -1

    if (is_video):
        filepath = frame_capture(context, url)
        load_file(context, filepath, callback)
    else:
        load_sync(context, url, callback, normalize_url_func)


def load_sync(context, url, callback, normalize_url_func):
    using_proxy = context.config.HTTP_LOADER_PROXY_HOST and context.config.HTTP_LOADER_PROXY_PORT
    if using_proxy or context.config.HTTP_LOADER_CURL_ASYNC_HTTP_CLIENT:
        http_client_implementation = 'tornado.curl_httpclient.CurlAsyncHTTPClient'
        prepare_curl_callback = _get_prepare_curl_callback(context.config)
    else:
        http_client_implementation = None  # default
        prepare_curl_callback = None

    tornado.httpclient.AsyncHTTPClient.configure(
        http_client_implementation,
        max_clients=context.config.HTTP_LOADER_MAX_CLIENTS)
    client = tornado.httpclient.AsyncHTTPClient()

    user_agent = None
    headers = {
        'Accept': 'image/*;q=0.9,*/*;q=0.1'
    }
    if context.config.HTTP_LOADER_FORWARD_ALL_HEADERS:
        headers = context.request_handler.request.headers
    else:
        if context.config.HTTP_LOADER_FORWARD_USER_AGENT:
            if 'User-Agent' in context.request_handler.request.headers:
                user_agent = context.request_handler.request.headers[
                    'User-Agent']
        if context.config.HTTP_LOADER_FORWARD_HEADERS_WHITELIST:
            for header_key in context.config.HTTP_LOADER_FORWARD_HEADERS_WHITELIST:
                if header_key in context.request_handler.request.headers:
                    headers[
                        header_key] = context.request_handler.request.headers[
                            header_key]

    if user_agent is None and 'User-Agent' not in headers:
        user_agent = context.config.HTTP_LOADER_DEFAULT_USER_AGENT

    url = normalize_url_func(url)
    req = tornado.httpclient.HTTPRequest(
        url=url,
        headers=headers,
        connect_timeout=context.config.HTTP_LOADER_CONNECT_TIMEOUT,
        request_timeout=context.config.HTTP_LOADER_REQUEST_TIMEOUT,
        follow_redirects=context.config.HTTP_LOADER_FOLLOW_REDIRECTS,
        max_redirects=context.config.HTTP_LOADER_MAX_REDIRECTS,
        user_agent=user_agent,
        proxy_host=encode(context.config.HTTP_LOADER_PROXY_HOST),
        proxy_port=context.config.HTTP_LOADER_PROXY_PORT,
        proxy_username=encode(context.config.HTTP_LOADER_PROXY_USERNAME),
        proxy_password=encode(context.config.HTTP_LOADER_PROXY_PASSWORD),
        ca_certs=encode(context.config.HTTP_LOADER_CA_CERTS),
        client_key=encode(context.config.HTTP_LOADER_CLIENT_KEY),
        client_cert=encode(context.config.HTTP_LOADER_CLIENT_CERT),
        validate_cert=context.config.HTTP_LOADER_VALIDATE_CERTS,
        prepare_curl_callback=prepare_curl_callback)

    start = datetime.datetime.now()
    client.fetch(
        req,
        callback=partial(
            return_contents,
            url=url,
            callback=callback,
            context=context,
            req_start=start))


def encode(string):
    return None if string is None else string.encode('ascii')


def _get_prepare_curl_callback(config):
    if config.HTTP_LOADER_CURL_LOW_SPEED_TIME == 0 or config.HTTP_LOADER_CURL_LOW_SPEED_LIMIT == 0:
        return None

    class CurlOpts:
        def __init__(self, config):
            self.config = config

        def prepare_curl_callback(self, curl):
            curl.setopt(curl.LOW_SPEED_TIME,
                        self.config.HTTP_LOADER_CURL_LOW_SPEED_TIME)
            curl.setopt(curl.LOW_SPEED_LIMIT,
                        self.config.HTTP_LOADER_CURL_LOW_SPEED_LIMIT)

    return CurlOpts(config).prepare_curl_callback
