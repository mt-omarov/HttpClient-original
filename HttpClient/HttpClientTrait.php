<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpClient;

use Symfony\Component\HttpClient\Exception\InvalidArgumentException;
use Symfony\Component\HttpClient\Exception\TransportException;

/**
 * Provides the common logic from writing HttpClientInterface implementations.
 *
 * All private methods are static to prevent implementers from creating memory leaks via circular references.
 *
 * @author Nicolas Grekas <p@tchwork.com>
 */
trait HttpClientTrait
{
    private static int $CHUNK_SIZE = 16372;

    public function withOptions(array $options): static
    {
        $clone = clone $this;
        $clone->defaultOptions = self::mergeDefaultOptions($options, $this->defaultOptions);

        return $clone;
    }

    /**
     * Validates and normalizes method, URL and options, and merges them with defaults.
     *
     * @throws InvalidArgumentException When a not-supported option is found
     */
    private static function prepareRequest(?string $method, ?string $url, array $options, array $defaultOptions = [], bool $allowExtraOptions = false): array
    {
        // если название метода указано, проверяется его корректность
        if (null !== $method) {
            // здесь проверяется, что метод содержит только буквы верхнего регистра
            if (\strlen($method) !== strspn($method, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')) {
                throw new InvalidArgumentException(sprintf('Invalid HTTP method "%s", only uppercase letters are accepted.', $method));
            }
            if (!$method) {
                throw new InvalidArgumentException('The HTTP method cannot be empty.');
            }
        }
        // тут происходит склеивание передаваемых опций с опциями по умолчанию, валидация и парсинг url-запроса и обработка исключений.
        $options = self::mergeDefaultOptions($options, $defaultOptions, $allowExtraOptions);

        // В случае, если буфер не определен, будет записан true.
        // После выше использованной функции массивы опций были склеены и буфер обязательно будет что-то содержать.
        // Так, при создании объекта CurlHttpClient с пустыми параметрами, в defaultOptions будут заранее определенные параметры,
        //    в том числе buffer, который по умолчанию всегда true. Отсюда следует, что если в передаваемых параметрах не будет ничего указано,
        //    то при склеивании в массиве options['buffer'] будет содержаться defaultOptions['buffer'] === true.
        $buffer = $options['buffer'] ?? true;

        // в случае, если в buffer будет записан Closure (функция self::shouldBuffer())
        // здесь возникнут проблемы с @stream_get_meta_data и получением meta-данных.
        if ($buffer instanceof \Closure) {
            $options['buffer'] = static function (array $headers) use ($buffer) {
                if (!\is_bool($buffer = $buffer($headers))) {
                    if (!\is_array($bufferInfo = @stream_get_meta_data($buffer))) {
                        throw new \LogicException(sprintf('The closure passed as option "buffer" must return bool or stream resource, got "%s".', get_debug_type($buffer)));
                    }

                    if (false === strpbrk($bufferInfo['mode'], 'acew+')) {
                        throw new \LogicException(sprintf('The stream returned by the closure passed as option "buffer" must be writeable, got mode "%s".', $bufferInfo['mode']));
                    }
                }

                return $buffer;
            };
        } elseif (!\is_bool($buffer)) {
            if (!\is_array($bufferInfo = @stream_get_meta_data($buffer))) {
                throw new InvalidArgumentException(sprintf('Option "buffer" must be bool, stream resource or Closure, "%s" given.', get_debug_type($buffer)));
            }

            if (false === strpbrk($bufferInfo['mode'], 'acew+')) {
                throw new InvalidArgumentException(sprintf('The stream in option "buffer" must be writeable, mode "%s" given.', $bufferInfo['mode']));
            }
        }

        if (isset($options['json'])) {
            if (isset($options['body']) && '' !== $options['body']) {
                throw new InvalidArgumentException('Define either the "json" or the "body" option, setting both is not supported.');
            }
            $options['body'] = self::jsonEncode($options['json']);
            unset($options['json']);

            if (!isset($options['normalized_headers']['content-type'])) {
                $options['normalized_headers']['content-type'] = ['Content-Type: application/json'];
            }
        }

        if (!isset($options['normalized_headers']['accept'])) {
            $options['normalized_headers']['accept'] = ['Accept: */*'];
        }

        if (isset($options['body'])) {
            if (\is_array($options['body']) && (!isset($options['normalized_headers']['content-type'][0]) || !str_contains($options['normalized_headers']['content-type'][0], 'application/x-www-form-urlencoded'))) {
                $options['normalized_headers']['content-type'] = ['Content-Type: application/x-www-form-urlencoded'];
            }

            $options['body'] = self::normalizeBody($options['body']);

            if (\is_string($options['body'])
                && (string) \strlen($options['body']) !== substr($h = $options['normalized_headers']['content-length'][0] ?? '', 16)
                && ('' !== $h || '' !== $options['body'])
            ) {
                if ('chunked' === substr($options['normalized_headers']['transfer-encoding'][0] ?? '', \strlen('Transfer-Encoding: '))) {
                    unset($options['normalized_headers']['transfer-encoding']);
                    $options['body'] = self::dechunk($options['body']);
                }

                $options['normalized_headers']['content-length'] = [substr_replace($h ?: 'Content-Length: ', \strlen($options['body']), 16)];
            }
        }

        if (isset($options['peer_fingerprint'])) {
            $options['peer_fingerprint'] = self::normalizePeerFingerprint($options['peer_fingerprint']);
        }

        // Validate on_progress
        if (isset($options['on_progress']) && !\is_callable($onProgress = $options['on_progress'])) {
            throw new InvalidArgumentException(sprintf('Option "on_progress" must be callable, "%s" given.', get_debug_type($onProgress)));
        }

        if (\is_array($options['auth_basic'] ?? null)) {
            $count = \count($options['auth_basic']);
            if ($count <= 0 || $count > 2) {
                throw new InvalidArgumentException(sprintf('Option "auth_basic" must contain 1 or 2 elements, "%s" given.', $count));
            }

            $options['auth_basic'] = implode(':', $options['auth_basic']);
        }

        if (!\is_string($options['auth_basic'] ?? '')) {
            throw new InvalidArgumentException(sprintf('Option "auth_basic" must be string or an array, "%s" given.', get_debug_type($options['auth_basic'])));
        }

        if (isset($options['auth_bearer'])) {
            if (!\is_string($options['auth_bearer'])) {
                throw new InvalidArgumentException(sprintf('Option "auth_bearer" must be a string, "%s" given.', get_debug_type($options['auth_bearer'])));
            }
            if (preg_match('{[^\x21-\x7E]}', $options['auth_bearer'])) {
                throw new InvalidArgumentException('Invalid character found in option "auth_bearer": '.json_encode($options['auth_bearer']).'.');
            }
        }

        if (isset($options['auth_basic'], $options['auth_bearer'])) {
            throw new InvalidArgumentException('Define either the "auth_basic" or the "auth_bearer" option, setting both is not supported.');
        }

        if (null !== $url) {
            // Merge auth with headers
            if (($options['auth_basic'] ?? false) && !($options['normalized_headers']['authorization'] ?? false)) {
                $options['normalized_headers']['authorization'] = ['Authorization: Basic '.base64_encode($options['auth_basic'])];
            }
            // Merge bearer with headers
            if (($options['auth_bearer'] ?? false) && !($options['normalized_headers']['authorization'] ?? false)) {
                $options['normalized_headers']['authorization'] = ['Authorization: Bearer '.$options['auth_bearer']];
            }

            unset($options['auth_basic'], $options['auth_bearer']);

            // Parse base URI
            if (\is_string($options['base_uri'])) {
                $options['base_uri'] = self::parseUrl($options['base_uri']);
            }

            // Validate and resolve URL
            $url = self::parseUrl($url, $options['query']);
            $url = self::resolveUrl($url, $options['base_uri'], $defaultOptions['query'] ?? []);
        }

        // Finalize normalization of options
        $options['http_version'] = (string) ($options['http_version'] ?? '') ?: null;
        if (0 > $options['timeout'] = (float) ($options['timeout'] ?? \ini_get('default_socket_timeout'))) {
            $options['timeout'] = 172800.0; // 2 days
        }

        $options['max_duration'] = isset($options['max_duration']) ? (float) $options['max_duration'] : 0;
        $options['headers'] = array_merge(...array_values($options['normalized_headers']));

        return [$url, $options];
    }

    /**
     * @throws InvalidArgumentException When an invalid option is found
     */
    private static function mergeDefaultOptions(array $options, array $defaultOptions, bool $allowExtraOptions = false): array
    {
        // сохраняется переформатированный массив передаваемых данных с помощью функции normalizedHeaders
        $options['normalized_headers'] = self::normalizeHeaders($options['headers'] ?? []);

        // Если основной массив данных определён, не равен false и null,
        // то ранее созданный массив объединяется с нормализованными по тому же правилу записями основного массива опций.
        // Причем при совпадающих ключах правый массив игнорируется.
        if ($defaultOptions['headers'] ?? false) {
            $options['normalized_headers'] += self::normalizeHeaders($defaultOptions['headers']);
        }

        // объединяет все подмассивы в один общий
        $options['headers'] = array_merge(...array_values($options['normalized_headers']) ?: [[]]);

        // resolve определяет, нужно ли cURL автоматически преобразовывать доменное имя хоста в IP-адрес.
        // resolve может содержать список доменных имен и соответствующих им IP-адресов.
        // Подобная информация, судя по всему, позволяет ускорить подключение.
        if ($resolve = $options['resolve'] ?? false) {
            $options['resolve'] = [];
            foreach ($resolve as $k => $v) {
                // Через parseUrl происходит разбиение url-адреса на части, его валидация, склеивание
                // передаваемых параметров с основными, а в конце возврат преобразованного url-адреса по частям
                // в качестве словаря.
                // В данном случае с помощью ключа 'authority' функция возвращает часть url-запроса, содержащего:
                    // если есть сам хост, имя и пароль: username+password+host,
                    // если есть хост и имя, но пароля нет: username+host,
                    // если есть хост, нет имени и пароля (или есть пароль и нет имени): host,
                    // если нет хоста: null.
                // Через substr(url, 2) в качестве ключа будет использоваться запись "username+pass+host", начиная с 3го символа.
                // В результате в массиве $options['resolve'] под ключом доменного имени будет записан IP-адрес сети.
                $options['resolve'][substr(self::parseUrl('http://'.$k)['authority'], 2)] = (string) $v;
            }
        }

        // Option "query" is never inherited from defaults
        $options['query'] ??= [];

        // объединение массивов
        $options += $defaultOptions;

        // если в полученном массиве данных есть пустые поля, они заполняются из массива emptyDefaults
        if (isset(self::$emptyDefaults)) {
            foreach (self::$emptyDefaults as $k => $v) {
                if (!isset($options[$k])) {
                    $options[$k] = $v;
                }
            }
        }

        if (isset($defaultOptions['extra'])) {
            $options['extra'] += $defaultOptions['extra'];
        }

        // если расшифровка доменных имен доступна и для массива по умолчанию, то объединенный массив
        // доменных имен и их IP обновляется.
        if ($resolve = $defaultOptions['resolve'] ?? false) {
            foreach ($resolve as $k => $v) {
                $options['resolve'] += [substr(self::parseUrl('http://'.$k)['authority'], 2) => (string) $v];
            }
        }

        if ($allowExtraOptions || !$defaultOptions) {
            return $options;
        }

        // Look for unsupported options
        foreach ($options as $name => $v) {
            if (\array_key_exists($name, $defaultOptions) || 'normalized_headers' === $name) {
                continue;
            }

            // эту часть кода надо переписать
            if ('auth_ntlm' === $name) {
                if (!\extension_loaded('curl')) {
                    $msg = 'try installing the "curl" extension to use "%s" instead.';
                } else {
                    $msg = 'try using "%s" instead.';
                }

                throw new InvalidArgumentException(sprintf('Option "auth_ntlm" is not supported by "%s", '.$msg, __CLASS__, CurlHttpClient::class));
            }

            if ('vars' === $name) {
                throw new InvalidArgumentException(sprintf('Option "vars" is not supported by "%s", try using "%s" instead.', __CLASS__, UriTemplateHttpClient::class));
            }

            $alternatives = [];

            foreach ($defaultOptions as $k => $v) {
                if (levenshtein($name, $k) <= \strlen($name) / 3 || str_contains($k, $name)) {
                    $alternatives[] = $k;
                }
            }

            throw new InvalidArgumentException(sprintf('Unsupported option "%s" passed to "%s", did you mean "%s"?', $name, __CLASS__, implode('", "', $alternatives ?: array_keys($defaultOptions))));
        }

        return $options;
    }

    /**
     * @return string[][]
     *
     * @throws InvalidArgumentException When an invalid header is found
     */
    private static function normalizeHeaders(array $headers): array
    {
        $normalizedHeaders = [];

        foreach ($headers as $name => $values) {
            // если значение $value можно преобразовать в string, это и делаем
            if ($values instanceof \Stringable) {
                $values = (string) $values;
            }

            // если ключ является числом и при этом $value является строкой, нужно вытащить название поля из строки $value
            if (\is_int($name)) {
                if (!\is_string($values)) {
                    throw new InvalidArgumentException(sprintf('Invalid value for header "%s": expected string, "%s" given.', $name, get_debug_type($values)));
                }
                [$name, $values] = explode(':', $values, 2);
                $values = [ltrim($values)];
            // иначе, если $value не является массивом или любым итерируемым объектом и объектом, преобразуем его в массив
            } elseif (!is_iterable($values)) {
                if (\is_object($values)) {
                    throw new InvalidArgumentException(sprintf('Invalid value for header "%s": expected string, "%s" given.', $name, get_debug_type($values)));
                }

                $values = (array) $values;
            }

            // далее мы перезаписываем элемент словаря "$name: [$value's]" по следующему правилу:
            // $name: [$name: $value, $name: $value и т.д.]
            $lcName = strtolower($name);
            $normalizedHeaders[$lcName] = [];

            foreach ($values as $value) {
                $normalizedHeaders[$lcName][] = $value = $name.': '.$value;

                if (\strlen($value) !== strcspn($value, "\r\n\0")) {
                    throw new InvalidArgumentException(sprintf('Invalid header: CR/LF/NUL found in "%s".', $value));
                }
            }
        }

        return $normalizedHeaders;
    }

    /**
     * @param array|string|resource|\Traversable|\Closure $body
     *
     * @return string|resource|\Closure
     *
     * @throws InvalidArgumentException When an invalid body is passed
     */
    private static function normalizeBody($body)
    {
        if (\is_array($body)) {
            array_walk_recursive($body, $caster = static function (&$v) use (&$caster) {
                if (\is_object($v)) {
                    if ($vars = get_object_vars($v)) {
                        array_walk_recursive($vars, $caster);
                        $v = $vars;
                    } elseif (method_exists($v, '__toString')) {
                        $v = (string) $v;
                    }
                }
            });

            return http_build_query($body, '', '&');
        }

        if (\is_string($body)) {
            return $body;
        }

        $generatorToCallable = static fn (\Generator $body): \Closure => static function () use ($body) {
            while ($body->valid()) {
                $chunk = $body->current();
                $body->next();

                if ('' !== $chunk) {
                    return $chunk;
                }
            }

            return '';
        };

        if ($body instanceof \Generator) {
            return $generatorToCallable($body);
        }

        if ($body instanceof \Traversable) {
            return $generatorToCallable((static function ($body) { yield from $body; })($body));
        }

        if ($body instanceof \Closure) {
            $r = new \ReflectionFunction($body);
            $body = $r->getClosure();

            if ($r->isGenerator()) {
                $body = $body(self::$CHUNK_SIZE);

                return $generatorToCallable($body);
            }

            return $body;
        }

        if (!\is_array(@stream_get_meta_data($body))) {
            throw new InvalidArgumentException(sprintf('Option "body" must be string, stream resource, iterable or callable, "%s" given.', get_debug_type($body)));
        }

        return $body;
    }

    private static function dechunk(string $body): string
    {
        $h = fopen('php://temp', 'w+');
        stream_filter_append($h, 'dechunk', \STREAM_FILTER_WRITE);
        fwrite($h, $body);
        $body = stream_get_contents($h, -1, 0);
        rewind($h);
        ftruncate($h, 0);

        if (fwrite($h, '-') && '' !== stream_get_contents($h, -1, 0)) {
            throw new TransportException('Request body has broken chunked encoding.');
        }

        return $body;
    }

    /**
     * @throws InvalidArgumentException When an invalid fingerprint is passed
     */
    private static function normalizePeerFingerprint(mixed $fingerprint): array
    {
        if (\is_string($fingerprint)) {
            $fingerprint = match (\strlen($fingerprint = str_replace(':', '', $fingerprint))) {
                32 => ['md5' => $fingerprint],
                40 => ['sha1' => $fingerprint],
                44 => ['pin-sha256' => [$fingerprint]],
                64 => ['sha256' => $fingerprint],
                default => throw new InvalidArgumentException(sprintf('Cannot auto-detect fingerprint algorithm for "%s".', $fingerprint)),
            };
        } elseif (\is_array($fingerprint)) {
            foreach ($fingerprint as $algo => $hash) {
                $fingerprint[$algo] = 'pin-sha256' === $algo ? (array) $hash : str_replace(':', '', $hash);
            }
        } else {
            throw new InvalidArgumentException(sprintf('Option "peer_fingerprint" must be string or array, "%s" given.', get_debug_type($fingerprint)));
        }

        return $fingerprint;
    }

    /**
     * @throws InvalidArgumentException When the value cannot be json-encoded
     */
    private static function jsonEncode(mixed $value, int $flags = null, int $maxDepth = 512): string
    {
        $flags ??= \JSON_HEX_TAG | \JSON_HEX_APOS | \JSON_HEX_AMP | \JSON_HEX_QUOT | \JSON_PRESERVE_ZERO_FRACTION;

        try {
            $value = json_encode($value, $flags | \JSON_THROW_ON_ERROR, $maxDepth);
        } catch (\JsonException $e) {
            throw new InvalidArgumentException('Invalid value for "json" option: '.$e->getMessage());
        }

        return $value;
    }

    /**
     * Resolves a URL against a base URI.
     *
     * @see https://tools.ietf.org/html/rfc3986#section-5.2.2
     *
     * @throws InvalidArgumentException When an invalid URL is passed
     */
    private static function resolveUrl(array $url, ?array $base, array $queryDefaults = []): array
    {
        if (null !== $base && '' === ($base['scheme'] ?? '').($base['authority'] ?? '')) {
            throw new InvalidArgumentException(sprintf('Invalid "base_uri" option: host or scheme is missing in "%s".', implode('', $base)));
        }

        if (null === $url['scheme'] && (null === $base || null === $base['scheme'])) {
            throw new InvalidArgumentException(sprintf('Invalid URL: scheme is missing in "%s". Did you forget to add "http(s)://"?', implode('', $base ?? $url)));
        }

        if (null === $base && '' === $url['scheme'].$url['authority']) {
            throw new InvalidArgumentException(sprintf('Invalid URL: no "base_uri" option was provided and host or scheme is missing in "%s".', implode('', $url)));
        }

        if (null !== $url['scheme']) {
            $url['path'] = self::removeDotSegments($url['path'] ?? '');
        } else {
            if (null !== $url['authority']) {
                $url['path'] = self::removeDotSegments($url['path'] ?? '');
            } else {
                if (null === $url['path']) {
                    $url['path'] = $base['path'];
                    $url['query'] ??= $base['query'];
                } else {
                    if ('/' !== $url['path'][0]) {
                        if (null === $base['path']) {
                            $url['path'] = '/'.$url['path'];
                        } else {
                            $segments = explode('/', $base['path']);
                            array_splice($segments, -1, 1, [$url['path']]);
                            $url['path'] = implode('/', $segments);
                        }
                    }

                    $url['path'] = self::removeDotSegments($url['path']);
                }

                $url['authority'] = $base['authority'];

                if ($queryDefaults) {
                    $url['query'] = '?'.self::mergeQueryString(substr($url['query'] ?? '', 1), $queryDefaults, false);
                }
            }

            $url['scheme'] = $base['scheme'];
        }

        if ('' === ($url['path'] ?? '')) {
            $url['path'] = '/';
        }

        if ('?' === ($url['query'] ?? '')) {
            $url['query'] = null;
        }

        return $url;
    }

    /**
     * Parses a URL and fixes its encoding if needed.
     *
     * @throws InvalidArgumentException When an invalid URL is passed
     */
    private static function parseUrl(string $url, array $query = [], array $allowedSchemes = ['http' => 80, 'https' => 443]): array
    {
        // если встроенная функция не смогла разбить url по частям, то она возвращает false
        if (false === $parts = parse_url($url)) {
            throw new InvalidArgumentException(sprintf('Malformed URL "%s".', $url));
        }

        // Если передаваемый параметр query существует, то мы перезаписываем часть url[query], объединяя эти два массива значений.
        // Ф-ция mergeQueryString вернёт строку параметров, которые, при наличии в обоих query очередях, будут перезаписаны из
        // передаваемого массива параметров $query. Им отдаётся предпочтение, т.к. флаг replace установлен в true.
        if ($query) {
            $parts['query'] = self::mergeQueryString($parts['query'] ?? null, $query, true);
        }

        // записываем значение порта или 0, если его нет в url-запросе
        $port = $parts['port'] ?? 0;

        // если url-запрос содержит протокол подключения (http или https)
        if (null !== $scheme = $parts['scheme'] ?? null) {
            // если используемый параметр есть в словаре поддерживаемых протоколов, то всё ок, иначе ошибка
            if (!isset($allowedSchemes[$scheme = strtolower($scheme)])) {
                throw new InvalidArgumentException(sprintf('Unsupported scheme in "%s".', $url));
            }

            // если ранее опреденное значение порта из url совпадает с числом из словаря по ключу параметра schema,
            // то в port запишется 0, иначе запишется сам $port.
            $port = $allowedSchemes[$scheme] === $port ? 0 : $port;
            $scheme .= ':';
        }

        // тут происходит валидация хоста
        if (null !== $host = $parts['host'] ?? null) {
            // Константа INTL_IDNA_VARIANT_UTS46 определяет тип IDN-формата при проверке доменного имени,
            // вторая часть if-условия проверяет, содержится ли в хосте символы, кодирующиеся более, чем одним байтом.
            // Если константа не определена и хост содержит такие символы, выбрасывается ошибка.
            if (!\defined('INTL_IDNA_VARIANT_UTS46') && preg_match('/[\x80-\xFF]/', $host)) {
                throw new InvalidArgumentException(sprintf('Unsupported IDN "%s", try enabling the "intl" PHP extension or running "composer require symfony/polyfill-intl-idn".', $host));
            }

            // наиболее интересная часть при переносе на кпхп, оно не будет работать из-за констант
            // Данная часть кода позволяет преобразовать доменное имя в ASCII формат и таким образом избавиться от использования
            // национального алфавита в запросе. Функция idn_to_ascii берётся из библиотеки intl и требует предопределенный набор числовых констант
            // кроме того, библиотека требует следующие зависимости: PHP 5 >= 5.3.0, PHP 7, PHP 8, PECL intl >= 1.0.2, PECL idn >= 0.1.
            $host = \defined('INTL_IDNA_VARIANT_UTS46') ? idn_to_ascii($host, \IDNA_DEFAULT | \IDNA_USE_STD3_RULES | \IDNA_CHECK_BIDI | \IDNA_CHECK_CONTEXTJ | \IDNA_NONTRANSITIONAL_TO_ASCII, \INTL_IDNA_VARIANT_UTS46) ?: strtolower($host) : strtolower($host);
            // к хосту, если значение порта определено, дописывается строка ":номер порта".
            $host .= $port ? ':'.$port : '';
        }

        // происходит окончательная валидация частей url-запроса
        foreach (['user', 'pass', 'path', 'query', 'fragment'] as $part) {
            if (!isset($parts[$part])) {
                continue;
            }

            // чтобы убедиться в корректности url-запроса, в том, что он не содержит неподдерживаемых символов,
            // все закодированные url-символы сначала декодируются в обычные символы, а после кодируются обратно.
            if (str_contains($parts[$part], '%')) {
                // https://tools.ietf.org/html/rfc3986#section-2.3
                $parts[$part] = preg_replace_callback('/%(?:2[DE]|3[0-9]|[46][1-9A-F]|5F|[57][0-9A]|7E)++/i', fn ($m) => rawurldecode($m[0]), $parts[$part]);
            }
            // теперь вся строка вновь кодируется
            // https://tools.ietf.org/html/rfc3986#section-3.3
            $parts[$part] = preg_replace_callback("#[^-A-Za-z0-9._~!$&/'()[\]*+,;=:@\\\\^`{|}%]++#", fn ($m) => rawurlencode($m[0]), $parts[$part]);
        }

        return [
            // возврат протокола
            'scheme' => $scheme,
            // возврат склеенного (имени пользователя + пароль (если пароль есть))(если имя пользователь есть) и хоста
            // если хост не определен, возвращается null
            'authority' => null !== $host ? '//'.(isset($parts['user']) ? $parts['user'].(isset($parts['pass']) ? ':'.$parts['pass'] : '').'@' : '').$host : null,
            'path' => isset($parts['path'][0]) ? $parts['path'] : null,
            'query' => isset($parts['query']) ? '?'.$parts['query'] : null,
            'fragment' => isset($parts['fragment']) ? '#'.$parts['fragment'] : null,
        ];
    }

    /**
     * Removes dot-segments from a path.
     *
     * @see https://tools.ietf.org/html/rfc3986#section-5.2.4
     *
     * @return string
     */
    private static function removeDotSegments(string $path)
    {
        $result = '';

        while (!\in_array($path, ['', '.', '..'], true)) {
            if ('.' === $path[0] && (str_starts_with($path, $p = '../') || str_starts_with($path, $p = './'))) {
                $path = substr($path, \strlen($p));
            } elseif ('/.' === $path || str_starts_with($path, '/./')) {
                $path = substr_replace($path, '/', 0, 3);
            } elseif ('/..' === $path || str_starts_with($path, '/../')) {
                $i = strrpos($result, '/');
                $result = $i ? substr($result, 0, $i) : '';
                $path = substr_replace($path, '/', 0, 4);
            } else {
                $i = strpos($path, '/', 1) ?: \strlen($path);
                $result .= substr($path, 0, $i);
                $path = substr($path, $i);
            }
        }

        return $result;
    }

    /**
     * Merges and encodes a query array with a query string.
     *
     * @throws InvalidArgumentException When an invalid query-string value is passed
     */
    private static function mergeQueryString(?string $queryString, array $queryArray, bool $replace): ?string
    {
        // данная функция используется при вызове конструктора для создания CurlClient.
        // она нужна при работе с определением IP-адреса доменного имени.
        // функция позволяет объединить передаваемые query параметры для создания url запроса и те,
        // что изначально содержатся в url и определяются с помощью встроенной функции url_parse.

        // таким образом, $queryString – это та самая query строка, которая определяется через url_parse, она может быть пустой. Будем называть её изначальной.
        // а $queryArray – это массив значений query, который дополнительно передаётся, он пустым быть по идее не должен.

        // если дополнительный массив параметров пуст, то объединять нечего и возврат очевиден
        if (!$queryArray) {
            return $queryString;
        }

        $query = [];
        // если изначальная строка query не пустая, нужно как-то её сложить в словарь для анализа
        if (null !== $queryString) {
            // здесь мы разбиваем строку на массив по разделителям
            foreach (explode('&', $queryString) as $v) {
                // только в случае, если полученная строка не является пустой
                if ('' !== $v) {
                    // urldecode позволяет преобразовать кодированные url символы в обычные человеческие буквы.
                    // в начале мы отделяем название переменной от её содержимой,
                    // далее докедируем закодированные url символы, а после записываем название параметра (ключ) в переменную $k.
                    $k = urldecode(explode('=', $v, 2)[0]);
                    // теперь можно создать новую переменную по такому ключу в $query.
                    // в случае, если такой ключ в массиве уже установлен, он будет
                    // склеен с рассматриваемой строкой $v формата "имя=значение" через символ &.
                    $query[$k] = (isset($query[$k]) ? $query[$k].'&' : '').$v;
                }
            }
        }

        // если флаг replace установлен, то мы убираем те параметры в query, которые отсутствуют в передаваемом массиве параметров
        if ($replace) {
            foreach ($queryArray as $k => $v) {
                if (null === $v) {
                    unset($query[$k]);
                }
            }
        }

        // записываем в переменную закодированную url последовательность параметров передаваемого массива
        $queryString = http_build_query($queryArray, '', '&', \PHP_QUERY_RFC3986);
        $queryArray = [];

        // далее, если полученная строка не пуста, происходит раскодировка некоторых закодированных символов
        // с помощью встроенной функции strtr.
        if ($queryString) {
            if (str_contains($queryString, '%')) {
                // https://tools.ietf.org/html/rfc3986#section-2.3 + some chars not encoded by browsers
                $queryString = strtr($queryString, [
                    '%21' => '!',
                    '%24' => '$',
                    '%28' => '(',
                    '%29' => ')',
                    '%2A' => '*',
                    '%2F' => '/',
                    '%3A' => ':',
                    '%3B' => ';',
                    '%40' => '@',
                    '%5B' => '[',
                    '%5C' => '\\',
                    '%5D' => ']',
                    '%5E' => '^',
                    '%60' => '`',
                    '%7C' => '|',
                ]);
            }

            // после декодировки неподдержимваемых символов, массив queryArray перезаписывается.
            // в цикле рассматривается каждый параметр формата "имя=значение" и в массив под ключом декодированного имени параметра
            // записывается сама строка "имя=значение" в url-формате (без полной декодировки).
            foreach (explode('&', $queryString) as $v) {
                $queryArray[rawurldecode(explode('=', $v, 2)[0])] = $v;
            }
        }

        // уже теперь полученный словарь параметров объединяется в строку с помощью встроенной функции emplode, используя между
        // элементами словаря разделитель '&'.
        // При чем, если флаг replace установлен, в строку преобразуется только массив переданных значений, в противном случае
        // будет использовано объединение массива и все совпадающие ключи будут использованы из $query (предпочтительным будет левый массив в выражении).
        return implode('&', $replace ? array_replace($query, $queryArray) : ($query + $queryArray));
    }

    /**
     * Loads proxy configuration from the same environment variables as curl when no proxy is explicitly set.
     */
    private static function getProxy(?string $proxy, array $url, ?string $noProxy): ?array
    {
        if (null === $proxy) {
            // Ignore HTTP_PROXY except on the CLI to work around httpoxy set of vulnerabilities
            $proxy = $_SERVER['http_proxy'] ?? (\in_array(\PHP_SAPI, ['cli', 'phpdbg'], true) ? $_SERVER['HTTP_PROXY'] ?? null : null) ?? $_SERVER['all_proxy'] ?? $_SERVER['ALL_PROXY'] ?? null;

            if ('https:' === $url['scheme']) {
                $proxy = $_SERVER['https_proxy'] ?? $_SERVER['HTTPS_PROXY'] ?? $proxy;
            }
        }

        if (null === $proxy) {
            return null;
        }

        $proxy = (parse_url($proxy) ?: []) + ['scheme' => 'http'];

        if (!isset($proxy['host'])) {
            throw new TransportException('Invalid HTTP proxy: host is missing.');
        }

        if ('http' === $proxy['scheme']) {
            $proxyUrl = 'tcp://'.$proxy['host'].':'.($proxy['port'] ?? '80');
        } elseif ('https' === $proxy['scheme']) {
            $proxyUrl = 'ssl://'.$proxy['host'].':'.($proxy['port'] ?? '443');
        } else {
            throw new TransportException(sprintf('Unsupported proxy scheme "%s": "http" or "https" expected.', $proxy['scheme']));
        }

        $noProxy ??= $_SERVER['no_proxy'] ?? $_SERVER['NO_PROXY'] ?? '';
        $noProxy = $noProxy ? preg_split('/[\s,]+/', $noProxy) : [];

        return [
            'url' => $proxyUrl,
            'auth' => isset($proxy['user']) ? 'Basic '.base64_encode(rawurldecode($proxy['user']).':'.rawurldecode($proxy['pass'] ?? '')) : null,
            'no_proxy' => $noProxy,
        ];
    }

    private static function shouldBuffer(array $headers): bool
    {
        // функция проверяет, что в массиве headers http-ответа содержится контент определенного типа.
        // в случае, если тип не обнаружен или не поддерживается, возвращается false.
        if (null === $contentType = $headers['content-type'][0] ?? null) {
            return false;
        }

        if (false !== $i = strpos($contentType, ';')) {
            $contentType = substr($contentType, 0, $i);
        }

        return $contentType && preg_match('#^(?:text/|application/(?:.+\+)?(?:json|xml)$)#i', $contentType);
    }
}
