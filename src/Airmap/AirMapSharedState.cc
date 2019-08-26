/****************************************************************************
 *
 *   (c) 2009-2016 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "AirMapSharedState.h"
#include "AirMapManager.h"

#include "airmap/authenticator.h"
#include "qjsonwebtoken.h"
#include <string>
#include <curl/curl.h>

using namespace airmap;

#define     AUTHENTICATE_URL        "https://asp.auth.airmap.com/realms/airmap/protocol/openid-connect/token"

#define     CONTENT_TYPE_HEADER     "Content-Type:application/x-www-form-urlencoded"
#define     API_KEY_HEADER          "X-API-Key"
#define     API_KEY                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjcmVkZW50aWFsX2lkIjoiY3JlZGVudGlhbHxnbllOTWQwZm54ME52a1RLbVoybTN0eUJSYjJvIiwiYXBwbGljYXRpb25faWQiOiJhcHBsaWNhdGlvbnxSNVhlTTd3Q1lFcFh4eFVwYVhEUWVINDhQRDRQIiwib3JnYW5pemF0aW9uX2lkIjoiZGV2ZWxvcGVyfFpCUG13bTdoRGJkWFludDhrRW5xYUNBcFptTDkiLCJpYXQiOjE1MzM4MzY0NDl9.odjj26xy90Y6IOVyOoUSOqxIMp6FmV7oytxyHDZRpM4"

#define     GRANT_TYPE              "password"
#define     CLIENT_ID               "zIbKn40yxJA54eGpMCEAw3nAFdAA9yCi"
#define     CLIENT_SECRET           "UgyeGsMEk2iAAM5-6H39UN4TWzw8aojyEl9yOHkGwSU03wrdI8z04q_j6hflKTmL"
#define     USERNAME                "winston@avy.eu"
#define     PASSWORD                "intheskywithdiamonds"
#define     SCOPE                   "openid"

QGC_LOGGING_CATEGORY(AirMapSharedStateLog, "AirMapSharedStateLog")

typedef enum {
    AUTH_SUCCESS,
    INVALID_CREDENTIALS,
    UNKNOWN_ERROR
}AuthStatus;

std::pair<AuthStatus,std::string> authenticate(std::string api_key,
                         std::string client_id,
                         std::string client_secret,
                         std::string username,
                         std::string password);

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

std::string getData(std::string buffer, std::string data_header);

void
AirMapSharedState::setSettings(const Settings& settings)
{
    logout();
    _settings = settings;
}

void
AirMapSharedState::doRequestWithLogin(const Callback& callback)
{
    if (isLoggedIn()) {
        callback(_loginToken);
    } else {
        login();
        _pendingRequests.enqueue(callback);
    }
}

//-- TODO:
//   For now, only anonymous login collects the (anonymous) pilot ID within login()
//   For autheticated logins, we need to collect it here as opposed to spread all over
//   the place as it is the case now.

void
AirMapSharedState::login()
{
    if (isLoggedIn() || _isLoginInProgress) {
        qCInfo(AirMapSharedStateLog()) << "Already Logged in";
        return;
    }
    _isLoginInProgress = true;
    qCInfo(AirMapSharedStateLog()) << "Attempting to Log in";
    if (_settings.userName == "") { //use anonymous login
        qCDebug(AirMapSharedStateLog) << "Anonymous authentication";
        Authenticator::AuthenticateAnonymously::Params params;
        params.id = "Anonymous";
        _client->authenticator().authenticate_anonymously(params,
                [this](const Authenticator::AuthenticateAnonymously::Result& result) {
            if (!_isLoginInProgress) { // was logout() called in the meanwhile?
                return;
            }
            if (result) {
                qCInfo(AirMapSharedStateLog) << "Successfully authenticated with AirMap: id="<< result.value().id.c_str();
                emit authStatus(AirspaceManager::AuthStatus::Anonymous);
                _loginToken = QString::fromStdString(result.value().id);
                qCInfo(AirMapSharedStateLog()) << "Login Token: " << _loginToken.toUtf8().constData();
                QJsonWebToken token = QJsonWebToken::fromTokenAndSecret(_loginToken, QString());
                QJsonDocument doc = token.getPayloadJDoc();
                QJsonObject json = doc.object();
                _pilotID = json.value("sub").toString();
                qCInfo(AirMapSharedStateLog) << "Anonymous pilot id:" << _pilotID;
                _processPendingRequests();
            } else {
                _pendingRequests.clear();
                emit authStatus(AirspaceManager::AuthStatus::Error);
                QString description = QString::fromStdString(result.error().description() ? result.error().description().get() : "");
                emit error("Failed to authenticate with AirMap",
                        QString::fromStdString(result.error().message()), description);
                qCInfo(AirMapSharedStateLog()) << "Failed to authenticate with AirMap:" << QString::fromStdString(result.error().message());
            }
        });
    } else {
        Authenticator::AuthenticateWithPassword::Params params;
        params.oauth.username = _settings.userName.toStdString();
        params.oauth.password = _settings.password.toStdString();
        params.oauth.client_id = _settings.clientID.toStdString();
        params.oauth.device_id = "QGroundControl";
        qCDebug(AirMapSharedStateLog) << "User authentication" << _settings.userName;
//        _client->authenticator().authenticate_with_password(params,
//                [this](const Authenticator::AuthenticateWithPassword::Result& result) {
//            if (!_isLoginInProgress) { // was logout() called in the meanwhile?
//                return;
//            }
//            if (result) {
//                qCDebug(AirMapSharedStateLog) << "Successfully authenticated with AirMap: id="<< result.value().id.c_str()<<", access="
//                        <<result.value().access.c_str();
//                qCInfo(AirMapSharedStateLog()) << "Successfully authenticated with AirMap";
//                emit authStatus(AirspaceManager::AuthStatus::Authenticated);
//                _loginToken = QString::fromStdString(result.value().id);
////                qCInfo(AirMapSharedStateLog()) << _loginToken.toUtf8().constData();
//                _processPendingRequests();
//            } else {
//                _pendingRequests.clear();
//                QString description = QString::fromStdString(result.error().description() ? result.error().description().get() : "");
//                emit authStatus(AirspaceManager::AuthStatus::Error);
//                emit error("Failed to authenticate with AirMap",
//                        QString::fromStdString(result.error().message()), description);
//                qCInfo(AirMapSharedStateLog()) << "Authentication failed.";
//            }
//        });
        std::pair<AuthStatus,std::string> result;
        result = authenticate(_settings.apiKey.toStdString(),
                              _settings.clientID.toStdString(),
                              CLIENT_SECRET,
                              _settings.userName.toStdString(),
                              _settings.password.toStdString());
        if (result.first == AUTH_SUCCESS) {
            qCInfo(AirMapSharedStateLog()) << "Successfully authenticated with AirMap";
            emit authStatus(AirspaceManager::AuthStatus::Authenticated);
            _loginToken = QString::fromStdString(getData(result.second,"access_token"));
            _processPendingRequests();
        }
        else {
            _pendingRequests.clear();
            //QString description = QString::fromStdString(result.error().description() ? result.error().description().get() : "");
            emit authStatus(AirspaceManager::AuthStatus::Error);
            emit error("Failed to authenticate with AirMap",QString("Something happened"),
                       QString("SOmething bad"));
                    //QString::fromStdString(static_cast<std::string>(result.first)), description);
            qCInfo(AirMapSharedStateLog()) << "Authentication failed.";
        }
    }
}

void
AirMapSharedState::_processPendingRequests()
{
    while (!_pendingRequests.isEmpty()) {
        _pendingRequests.dequeue()(_loginToken);
    }
}

void
AirMapSharedState::logout()
{
    _isLoginInProgress = false; // cancel if we're currently trying to login
    if (!isLoggedIn()) {
        return;
    }
    _pilotID.clear();
    _loginToken.clear();
    _pendingRequests.clear();
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    (static_cast<std::string*>(userp))->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

std::string getData(std::string buffer, std::string data_header)
{
    // TODO: collect end data
    data_header.append("\":");
    std::size_t start = buffer.find(data_header);
    if (start == std::string::npos)
    {
        return "";
    }
    else
    {
        start += data_header.length();
        if (buffer[start] == '\"')
            ++start;
        std::size_t end = buffer.find(",",start+1);
        if (end == std::string::npos)
        {
            return "";
        }
        else
        {
            if (buffer[end-1] == '\"')
                --end;
            return buffer.substr(start,end-start);
        }
    }
}

std::pair<AuthStatus,std::string> authenticate(std::string api_key = API_KEY,
                         std::string client_id = CLIENT_ID,
                         std::string client_secret = CLIENT_SECRET,
                         std::string username = USERNAME,
                         std::string password = PASSWORD)
{
    std::string readBuffer;
    CURL *curl;
    CURLcode res;
    struct curl_slist *headerlist = nullptr;
    AuthStatus result;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    std::string data = "grant_type=";
    data.append(GRANT_TYPE);
    data.append("&client_id=");
    data.append(client_id);
    data.append("&client_secret=");
    data.append(client_secret);
    data.append("&username=");
    data.append(username);
    data.append("&password=");
    data.append(password);
    data.append("&scope=");
    data.append(SCOPE);

    //std::cout << "POST data: " << data << std::endl;

    if(curl) {
      curl_easy_setopt(curl, CURLOPT_URL, AUTHENTICATE_URL);

      headerlist = curl_slist_append(headerlist, (std::string(API_KEY_HEADER) + ':' + api_key).c_str());
      headerlist = curl_slist_append(headerlist, CONTENT_TYPE_HEADER);

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

      res = curl_easy_perform(curl);
      curl_easy_cleanup(curl);

      //std::cout << "Res: " << res << std::endl;
      //std::cout << "Output size: " << readBuffer.length() << std::endl;
      //std::cout << readBuffer << std::endl;
      if (getData(readBuffer,"error").length() != 0) {
          result = INVALID_CREDENTIALS;
      }
      else {
          result = AUTH_SUCCESS;
      }
    }
    return std::make_pair(result,readBuffer);

}
