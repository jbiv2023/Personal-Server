/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <jansson.h>
#include <jwt.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

// phrase used to encode and decode
static const char *NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";
static bool
send_error(struct http_transaction *ta, enum http_response_status status, const char *fmt, ...);

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2) // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len - 2] = '\0'; // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL) // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    // for (;;)
    ta->is_authenticated = false;
    ta->token = NULL;
    while (true)
    {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF)) // empty CRLF
            return true;

        header[len - 2] = '\0';
        /* Each header field consists of a name followed by a
         * colon (":") and the field value. Field names are
         * case-insensitive. The field value MAY be preceded by
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skips the white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        // was !

        // Checks the field_name and sets relevant variabels
        if (strcasecmp(field_name, "Content-Length") == 0)
        {
            ta->req_content_len = atoi(field_value);
        }
        if (strcasecmp(field_name, "Cookie") == 0)
        {
            char *save;
            char *current;
            bool havePassedThruLoop = false;

            // loop split with simicolins and see each token
            // use strstr()
            // looking for auth_token=
            while ((current = strtok_r(havePassedThruLoop ? NULL : field_value, ";", &save)) != NULL)
            {
                while (*current == ' ' || *current == '\t')
                    current++;
                // what if there is one cookie?? no ;
                // current = strtok_r(field_value, ";", &save);
                havePassedThruLoop = true;
                if (current == NULL)
                {
                    current = field_value;
                }                

                if (STARTS_WITH(current, "auth_token="))
                {
                    // Adds 11 to get past "auth_token="
                    char *encoded = current + 11;
                    jwt_t *ymtoken;

                    bool success_decode = jwt_decode(&ymtoken, encoded, (const unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, strlen((char *)NEVER_EMBED_A_SECRET_IN_CODE));

                    //handle if it faild
                    if (success_decode)
                    {
                        continue;
                    }
                    // if its good do this
                    char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
                    
                    json_error_t error;
                    json_t *jgrants = json_loadb(grants, strlen(grants), 0, &error);

                    json_int_t exp, iat;

                    const char *sub;
                    json_unpack(jgrants, "{s:I, s:I, s:s}",
                                "exp", &exp, "iat", &iat, "sub", &sub);
                    /*check sub is user0*/
                    if (time(NULL) < exp && strcmp(sub, "user0") == 0)
                    {
                        ta->is_authenticated = true;
                        ta->token = grants;
                        // free (grants);
                        break;
                    }
                }
            }
        }
        // parsing stuff
        if (!strcasecmp(field_name, "Range"))
        {
            // range:field_value 10-20
            // if they wanted 10 to the end of the file 10-
            //strtok_r(header, ":", &endptr);
            // lets say i have 10 and 20...
            // set bool to true for below part
            // store them somewhere,.... transctioin struct, so static asset can access it
            ta->needToUpdate = true;
            char *range = strstr(field_value, "bytes=");

            if (range)
            {
                // Add 6 because it is the length of "bytes="
                char *what_we_need = range + 6;
                char *first_num = strtok(what_we_need, "-");
                if (first_num == NULL)
                {
                    continue;
                }
                char *second_num = strtok(NULL, "-");

                ta->start = (off_t)atoi(first_num);

                if (second_num)
                {
                    ta->end = (off_t)atoi(second_num);
                }
            }
            else
            {
                ta->end = 0;
            }
        }

        if (strcasecmp(field_name, "Connection") == 0)
        {
            // fieldvalue could either be "close" or "keep-alive"
            if (strcasecmp(field_value, "keep-alive"))
            {
                ta->req_version = HTTP_1_1;
                ta->keep_alive = true;
            }
            else if (strcasecmp(field_value, "close"))
            {
                ta->req_version = HTTP_1_0;
                ta->keep_alive = false;
            }
        }

        if (strcasecmp(field_name, "Version") == 0)
        {
            // Sets the correct http version
            if (strcasecmp(field_value, "HTTP/1.1"))
            {
                ta->req_version = HTTP_1_1;
            }
            else if (strcasecmp(field_value, "HTTP/1.0"))
            {
                ta->req_version = HTTP_1_0;
            }
        }
    }

    return true;
}

/* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void http_add_header(buffer_t *resp, char *key, char *fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction *ta, buffer_t *res)
{
    buffer_init(res, 80);

    if (ta->req_version == HTTP_1_1)
    {
        buffer_appends(res, "HTTP/1.1 ");
    }
    else
    {
        buffer_appends(res, "HTTP/1.0 ");
    }

    switch (ta->resp_status)
    {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    start_response(ta, &response);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t *response_and_headers[2] = {
        &response, &ta->resp_headers};

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 2);
    buffer_delete(&response);
    return rc != -1;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t response;
    start_response(ta, &response);

    buffer_t *response_and_headers[3] = {
        &response, &ta->resp_headers, &ta->resp_body};

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 3);
    buffer_delete(&response);
    return rc != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction *ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found",
                      bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";
    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";
    if (!strcasecmp(suffix, ".css"))
        return "text/css";
    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";
   
    

    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    if (strstr(req_path, ".."))
    {
        return send_error(ta, HTTP_NOT_FOUND, "File not found.");
    }

    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    // if(html5_fallback && STARTS_WITH("/", req_path)) {
    if (html5_fallback && strcmp("/", req_path) == 0)
    {
        snprintf(fname, sizeof fname, "%s/index.html", basedir);
    }

    // fname = mcc/users
    struct stat stt;
    int rcc = stat(fname, &stt);

    if (access(fname, F_OK) || rcc == -1 || S_ISDIR(stt.st_mode))
    {
        // printf("%s", "access(fname, F_OK");
        // if (errno == EACCES)
        //     return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        // else {
        if (html5_fallback)
        {
            // the third case where its like /some/path -> /some/path.html
            // snprintf (append on .html onto our fname)
            // see if therer is a /mcc/users.html

            // check return of strstr
            if (!strstr(req_path, ".html"))
            {
                snprintf(fname, sizeof fname, "%s%s.html", basedir, req_path);
                // snprintf(fname, sizeof fname, "%s.html", basedir);
            }

            // snprintf(fname, sizeof fname, "%s%s.html", basedir, req_path);

            if (access(fname, F_OK))
            {
                // change fname to be "/200.html"
                snprintf(fname, sizeof fname, "%s/200.html", basedir);
                if (access(fname, F_OK))
                {
                    return send_not_found(ta);
                }
            }
        }
        else
        {
            return send_not_found(ta);
        }
        // }
    }

    if (access(fname, R_OK))
    {
        if (errno == EACCES)
        {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        }
    }
    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    // directory
    if (S_ISDIR(st.st_mode))
    {
        return send_error(ta, HTTP_NOT_FOUND, "Not found.");
    }
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1)
    {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));

    // ctrl shift i
    // similaar approach to auth token
    // add range type header
    // change these to variiables

    // do this process headder functions
    // record infor in http transaction struct
    // offset ta
    // char* curr = strtok_r(field_value, ";", &save));
    // off_t start_time;
    // if(STARTS_WITH(curr, "bytes=")) {

    //     char* start = curr + 6;

    // }

    /// this is the video for chuncking
    // updataing stuff
    off_t from = 0, to = st.st_size - 1;

    // send you the range in the first place
    // teling the client that it can accept ranges

    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");

    if (ta->needToUpdate)
    {
        from = ta->start;

        if (ta->end != 0)
        {
            to = ta->end;
        }

        ta->resp_status = HTTP_PARTIAL_CONTENT;
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %d-%d/%d", from, to, st.st_size);
    }

    // check if need to update these vvalues from the process handle strokr thing abov3w
    // we can set a booleawn from the above thing... once strstr === range then set bool to true and
    // after we update:

    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}

static bool
handle_api(struct http_transaction *ta, char *req_path)
{

    // return send_error(ta, HTTP_NOT_FOUND, "API not implemented");
    // changed to strcmp because it gave:  error: comparison with string literal results in unspecified behavior
    if (strcmp(req_path, "/api/login") == 0)
    {
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        // If client supplies login information
        if (ta->req_method == HTTP_POST)
        {
            const char *password;
            const char *user;

            char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);

            json_error_t error;
            // parses the javascript object
            json_t *jgrants = json_loadb(body, ta->req_content_len, 0, &error);
            // jgrants: {"username":"user0","password":"thepassword"}

            // json_int_t user, password; from the client side

            // json_string(password);
            // json_string(user);

            if (jgrants == NULL)
            {
                // fprintf(stderr, "%s\n", body);
                return send_error(ta, HTTP_BAD_REQUEST, "Bad Request.");
            }

            // assigns the client text to a variable
            int upack = json_unpack(jgrants, "{s:s, s:s}",
                                    "username", &user, "password", &password);
            /*
            if the user name and the password of the user equals that its supposed to be
            make your cookie
                has the header and the body

            */
            if (upack != 0)
            {
                // fprintf(stderr, "return from unpack\n");
                return send_error(ta, HTTP_BAD_REQUEST, "Bad Request.");
            }

            if (strcmp(user, "user0") == 0 && strcmp(password, "thepassword") == 0)
            {
                // http_add_header(&ta->resp_headers, "Set-Cookie", "%s=%s", "auth_t", encoded);

                // code from jwt_demo_hs256
                jwt_t *mytoken;
                // if 0 is a good value
                // not zero is a bad value
                int rc = jwt_new(&mytoken);
                // if (!rc){        // dont die stay alive and !rc these things
                /*
                        encyption process
                        grant is like a key value pair that you
                        are adding to the token
                    */
                rc = jwt_add_grant(mytoken, "sub", "user0");
                // if (!rc){

                /*
                            just the current time stamp of the partiucular instance
                            the code sees this... it makes these variables:
                            iat = time at which the claim was issued
                            exp = the time at which the claim will expire
                        */
                // get_grant_jason
                time_t now = time(NULL);
                rc = jwt_add_grant_int(mytoken, "iat", now);
                //int iatTime = now;
                // if (!rc){

                // rc = jwt_add_grant_int(mytoken, "exp", now + 3600 * 24)

                rc = jwt_add_grant_int(mytoken, "exp", now + token_expiration_time);
                // int expTime = now + token_expiration_time;

                // if (!rc){

                rc = jwt_set_alg(mytoken, JWT_ALG_HS256,
                                 (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                                 strlen(NEVER_EMBED_A_SECRET_IN_CODE));
                // if (!rc){

                /*
                        convert thhe object into an encoded string to
                        be sent back to the client
                        why do you want to sentd  it
                            you want it to keep track of the user
                            the cookie
                        auth_token is the cookie name
                        look at the link to see the format to assign the cookie
                            name to the proper client (cookie name)
                        Then add it to the header with the add_header method

                        here
                    */

                char *encoded = jwt_encode_str(mytoken);

                /*
                            setting the cookie to the encoded value
                            setting the path to /
                            setting the expiration date
                        */
                if (rc)
                {
                }
                // now = time(NULL);
                // int token_expiration_time = now + 24 * 60 * 60;
                http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/; Max-Age=%d; SameSite=Lax; HttpOnly", encoded, token_expiration_time);

                char *grants = jwt_get_grants_json(mytoken, NULL);
                //char grants[2048] = {'\0'};
                //snprintf(grants, MAX_ERROR_LEN, "{\"exp\": %ld, \"iat\": %ld, \"sub\": \"user0\"}", now + token_expiration_time, now);
                buffer_appends(&ta->resp_body, grants);
                ta->resp_status = HTTP_OK;
                bool success = send_response(ta);
                jwt_free(mytoken);
                // printf("encoded as %s\nTry entering this at jwt.io\n", encoded);
                //return send_error(ta, HTTP_OK, grants);
                return success;
            }

            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");

            //    return send_error(ta, HTTP_OK, "Authentication Failed.");
        }

        // If client supplies token in a cookie
        else if (ta->req_method == HTTP_GET)
        {
            // either send same object again if authenticated
            // or empty object if not authenticated
            // header has bunch of stuff you have cookie header, one of them will be the offtoken
            /// look through the header to try to find the specific header
            // decodes well ur good == authentic
            /*
                 if token is authenticated and has not expired
                 (ta.is_authenticated == true)
                     claims is the decoded cookie
                    store this value to access it (should be saved in the above part)
                     return claim
                 else
                     return empty object
            */
            //char *grants = jwt_get_grants_json(&ta->token, NULL); // NULL means all
            // buffer append s so no third for buffer append

            // http_add_header(&ta->resp_headers, "Content-Type", "application/json");

            if (ta->token != NULL && ta->is_authenticated)
            {
                // buffer append here, not sure if correct
                buffer_appends(&ta->resp_body, ta->token);
            }
            else
            {
                buffer_appends(&ta->resp_body, "{}");
            }

            ta->resp_status = HTTP_OK;
            return send_response(ta);

        }
        else {
            return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "dummy");
        }
    }
    else if (strcmp(req_path, "/api/logout") == 0)
    {

        /*
            Log user out:
           Set-Cookie: auth_token=; Max-Age=0; Path=/
        */

        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly");

        ta->is_authenticated = false;
        ta->token = NULL;

        // ta->resp_status = HTTP_OK;
        // return send_response(ta);
        // free(ta);

        return send_error(ta, HTTP_OK, "{}");
    }
    else if (strcmp(req_path, "/api/video") == 0)
    {

        if (ta->req_method == HTTP_GET)
        {
            json_t *movies = json_array();

            DIR *dr = opendir(server_root);

            if (dr != NULL)
            {
                struct dirent *de;
                while ((de = readdir(dr)) != NULL)
                {
                    if (strstr(de->d_name, ".mp4"))
                    {
                        struct stat st;
                        char fname[PATH_MAX];
                        snprintf(fname, sizeof fname, "%s/%s", server_root, de->d_name);
                        //st.st_size
                        int rc = stat(fname, &st);
                        if (rc)
                        {
                            continue;
                        }
                         //printf("name = %s size = %ld\n", de->d_name, st.st_size);
                        json_t *obj = json_object();
                        json_object_set_new(obj, "name", json_string(de->d_name));
                        json_object_set_new(obj, "size", json_integer(st.st_size));
                        json_array_append_new(movies, obj);
                    }
                }
                // printf("%s\n", de->d_name);
                closedir(dr);
            }

            http_add_header(&ta->resp_headers, "Content-Type", "application/json");

            char *uno = json_dumps(movies, 0);
            json_decref(movies);
            if (uno == NULL)
            {
                buffer_appends(&ta->resp_body, "[]");
            }
            else
            {

                buffer_appends(&ta->resp_body, uno);
                free(uno);
            }
            ta->resp_status = HTTP_OK;
            return send_response(ta);
        }

        return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "Video Only Support Get");
    }
    return send_error(ta, HTTP_NOT_FOUND, "not implemented");
}

/* Set up an http client, associating it with a bufio buffer. */
void http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0)
    {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (STARTS_WITH(req_path, "/api"))
    {
        rc = handle_api(&ta, req_path);
    }
    else if (STARTS_WITH(req_path, "/private"))
    {

        if (ta.is_authenticated)
        {
            return handle_static_asset(&ta, server_root);
        }
        else
        {
            return send_error(&ta, HTTP_PERMISSION_DENIED, "Authentication failed.");
        }
    }
    else
    {
        rc = handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc && ta.req_version == HTTP_1_1;
}
