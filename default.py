import sys
import xbmc
import xbmcaddon
import xbmcplugin
import xbmcgui
import urllib.parse
import urllib.request
import json

from resources.lib.playhoster import play_hoster
from resources.lib.signaturehandler import SignatureHandler
from resources.lib.playhelper import play_m3u8_stream

def show_error_dialog(title, message):
    xbmcgui.Dialog().ok(title, message)

import threading
import time

import xbmcvfs as _xbmcvfs
_ADDON_DATA_PATH = _xbmcvfs.translatePath(
    "special://userdata/addon_data/plugin.video.vodkool/"
)
if not _xbmcvfs.exists(_ADDON_DATA_PATH):
    _xbmcvfs.mkdirs(_ADDON_DATA_PATH)
    xbmc.log(f"[vodkool] Addon-Datenverzeichnis erstellt: {_ADDON_DATA_PATH}", xbmc.LOGINFO)

sig_handler = SignatureHandler()

# ============= TOKEN-CACHING FIX (verhindert Rate-Limiting) =============
# Token-Cache als Modul-Level Variablen (einfach und stabil)
_token_cache = {"token": None, "time": 0, "validation_done": False}

def _get_cached_token():
    """Token mit Cache - vermeidet zu viele Server-Requests"""
    try:
        current_time = time.time()
        
        # Cache für 15 Minuten (900 Sekunden)
        if _token_cache["token"] and (current_time - _token_cache["time"]) < 900:
            xbmc.log(f"[vodkool] Token aus Cache (gültig noch {int(900 - (current_time - _token_cache['time']))}s)", xbmc.LOGDEBUG)
            return _token_cache["token"]
        
        # Erst aus File versuchen
        sd = sig_handler.read_signature()
        if sd and sd.get("mediahubmx-raw"):
            token = sd.get("mediahubmx-raw", "")
            xbmc.log(f"[vodkool] Token aus File geladen", xbmc.LOGINFO)
        else:
            # Nur wenn nötig: neuen Token holen
            token = sig_handler.get_new_signature()
            if token:
                sig_handler.save_signature(token)
                xbmc.log(f"[vodkool] Neuer Token geholt und gespeichert", xbmc.LOGINFO)
            else:
                xbmc.log(f"[vodkool] WARNUNG: Kein Token verfügbar!", xbmc.LOGWARNING)
                token = ""
        
        # Cache aktualisieren
        _token_cache["token"] = token
        _token_cache["time"] = current_time
        
        return token
        
    except Exception as e:
        # Bei Fehler: Fallback auf Original-Verhalten
        xbmc.log(f"[vodkool] Token-Cache Fehler: {e} - Fallback zu Original", xbmc.LOGERROR)
        try:
            sd = sig_handler.read_signature()
            return sd.get("mediahubmx-raw", "") if sd else ""
        except:
            return ""

# Token holen (mit Cache und Error-Handling)
signature_raw = _get_cached_token()

# Validierung NUR EINMAL pro Session starten
if signature_raw and not _token_cache["validation_done"]:
    _token_cache["validation_done"] = True
    
    def _validate_token():
        try:
            req = urllib.request.Request(
                "https://kool.to/mediahubmx.json",
                headers={"User-Agent": "Dezor/1.5.4", "mediahubmx-jwt": signature_raw}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                rj = json.loads(r.read())
            
            if (rj.get("error", "") or "").startswith("Malformed"):
                xbmc.log(f"[vodkool] Token ungültig, wird zurückgesetzt", xbmc.LOGWARNING)
                sig_handler.reset_signature()
                _token_cache["token"] = None
                _token_cache["time"] = 0
            else:
                sig_handler.save_signature(signature_raw)
                xbmc.log(f"[vodkool] Token erfolgreich validiert", xbmc.LOGINFO)
        except Exception as e:
            xbmc.log(f"[vodkool] Token-Validierung fehlgeschlagen: {e}", xbmc.LOGWARNING)
    
    threading.Thread(target=_validate_token, daemon=True).start()
    xbmc.log(f"[vodkool] Token-Validierung gestartet", xbmc.LOGDEBUG)

_action = dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?") if len(sys.argv) > 2 else "")).get("action", "")
# ========================================================================

HANDLE = int(sys.argv[1])

import random as _random_mod

_LOKKE_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) lokke/4.1.1 Chrome/106.0.5249.199 Electron/21.4.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) lokke/4.1.1 Chrome/108.0.5359.124 Electron/21.4.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) lokke/4.1.1 Chrome/110.0.5481.177 Electron/21.4.0 Safari/537.36",
]

def _kool_request(url):
    for ua in (_random_mod.choice(_LOKKE_UAS), "Mozilla/5.0"):
        try:
            headers = {
                "User-Agent": ua,
                "Referer": "https://www.kool.to/web-vod/",
                "Origin": "https://www.kool.to",
                "Accept-Language": "de",
            }
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=15)
            return json.loads(response.read().decode("utf-8"))
        except Exception as e:
            xbmc.log(f"[vodkool] _kool_request ua={ua[:30]} err={e}", xbmc.LOGWARNING)
    return {}

def _mhub_post(url, body):
    """POST-Request zur MediaHubMX API mit Signature"""
    token = _get_cached_token()
    if not token:
        raise Exception("Keine gueltige Signatur verfuegbar.")

    data = json.dumps(body).encode("utf-8")
    headers = {
        "accept": "*/*",
        "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-type": "application/json; charset=utf-8",
        "origin": "https://kool.to",
        "referer": "https://kool.to/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "mediahubmx-signature": token,
    }

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode("utf-8")
            result = json.loads(raw)
            xbmc.log(f"[vodkool] mhub POST erfolgreich: catalog_id={body.get('catalogId')}, items={len(result.get('items', result.get('data', [])))}", xbmc.LOGINFO)
            return result
    except Exception as e:
        xbmc.log(f"[vodkool] mhub POST Fehler: {e}, body={body}", xbmc.LOGERROR)
        raise

def _vod_catalog_fetch(catalog_id, cursor=0, search="", sort="", extra_filter=None):
    """
    Fetch VOD Catalog mit korrekten Parametern:
    - cursor IMMER int
    - filter IMMER dict (nie None)
    - id = catalogId (wie im Live-Pattern)
    """
    if not isinstance(cursor, int):
        try:
            cursor = int(cursor)
        except Exception:
            cursor = 0

    body = {
        "language": "de",
        "region": "AT",
        "catalogId": catalog_id,      # z.B. movie.popular / series.popular
        "id": catalog_id,
        "adult": False,
        "search": search or "",
        "sort": sort or "",
        "filter": extra_filter if isinstance(extra_filter, dict) else {},
        "cursor": cursor,
        "clientVersion": "3.0.3",
    }

    xbmc.log(f"[vodkool] VOD Request: catalog={catalog_id}, cursor={cursor}", xbmc.LOGINFO)
    j = _mhub_post("https://www.kool.to/mediahubmx-catalog.json", body)

    # Diagnose im Log
    if isinstance(j, dict):
        items_count = len(j.get('items', j.get('data', [])))
        next_cursor = j.get('nextCursor')
        xbmc.log(f"[vodkool] VOD Response: items={items_count}, nextCursor={next_cursor}, keys={list(j.keys())[:5]}", xbmc.LOGINFO)
    
    return j

def show_filme(next_id=None, genre=None, catalog_id="movie.popular"):
    try:
        # FIX: next_id kann "movie.popular" sein -> niemals blind int()
        cursor = int(next_id) if (next_id is not None and str(next_id).isdigit()) else 0

        flt = {}
        if genre:
            flt["genre"] = genre

        j = _vod_catalog_fetch(catalog_id=catalog_id, cursor=cursor, extra_filter=flt)

        # manche Antworten liefern items, andere data
        items = []
        if isinstance(j, dict):
            items = j.get("items") or j.get("data") or []

        if not items:
            xbmc.log(f"[vodkool] KEINE Filme fuer catalog={catalog_id} cursor={cursor}. Response keys: {list(j.keys()) if isinstance(j, dict) else 'nicht dict'}", xbmc.LOGWARNING)
            show_error_dialog("Keine Filme", f"Keine Filme gefunden für: {catalog_id}")
        else:
            xbmc.log(f"[vodkool] {len(items)} Filme geladen", xbmc.LOGINFO)

        for item in items:
            item_id = item.get("id", "")
            li = xbmcgui.ListItem(label=item.get("name", ""))
            li.setArt({"thumb": item.get("poster", "")})
            li.setInfo("video", {"plot": item.get("description", "")})
            url_params = urllib.parse.urlencode({
                "action": "hoster",
                "id": item_id,
                "season": "",
                "episode": "",
                "epid": item_id
            })
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)

        nxt = j.get("nextCursor") if isinstance(j, dict) else None
        if nxt is not None:
            li = xbmcgui.ListItem(label="Nächste Seite ▶")
            url_params = urllib.parse.urlencode({
                "action": "filme",
                "next": str(nxt),
                "catalog": catalog_id,
                **({"genre": genre} if genre else {})
            })
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)

    except Exception as e:
        xbmc.log(f"[vodkool] show_filme ERROR: {e}", xbmc.LOGERROR)
        show_error_dialog("Uuups!!!", f"Konnte Filme nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

def show_filme_trending(next_id=None):
    show_filme(next_id=next_id, catalog_id="movie.trending")

def show_filme_popular(next_id=None):
    show_filme(next_id=next_id, catalog_id="movie.popular")

def show_filme_filter():
    genres = [
        ("Action",          "Action"),
        ("Abenteuer",       "Abenteuer"),
        ("Animation",       "Animation"),
        ("Komoedie",        "Komödie"),
        ("Krimi",           "Krimi"),
        ("Dokumentarfilm",  "Dokumentarfilm"),
        ("Drama",           "Drama"),
        ("Familie",         "Familie"),
        ("Fantasy",         "Fantasy"),
        ("Historie",        "Historie"),
        ("Horror",          "Horror"),
        ("Musik",           "Musik"),
        ("Mystery",         "Mystery"),
        ("Liebesfilm",      "Liebesfilm"),
        ("Science Fiction", "Science Fiction"),
        ("TV-Film",         "TV-Film"),
        ("Thriller",        "Thriller"),
        ("Kriegsfilm",      "Kriegsfilm"),
        ("Western",         "Western"),
    ]
    for label, genre in genres:
        li = xbmcgui.ListItem(label=label)
        url_params = urllib.parse.urlencode({"action": "filme_genre", "genre": genre})
        xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    xbmcplugin.endOfDirectory(HANDLE)

def show_filme_year():
    jahre = [str(y) for y in range(2025, 1999, -1)]
    idx = xbmcgui.Dialog().select("Jahr wählen", jahre)
    if idx == -1:
        xbmcplugin.endOfDirectory(HANDLE)
        return
    jahr = jahre[idx]
    show_filme(catalog_id=f"movie.popular", extra_filter={"year": jahr})

def show_serien(next_id=None):
    url = f"https://www.kool.to/web-vod/api/list?id={next_id or 'series.popular'}"
    try:
        j = _kool_request(url)
        for item in j.get("data", []):
            li = xbmcgui.ListItem(label=item.get("name", ""))
            li.setArt({"thumb": item.get("poster", "")})
            li.setInfo("video", {"plot": item.get("description", "")})
            url_params = urllib.parse.urlencode({"action": "staffeln", "id": item.get("id", "")})
            _serie_params = f"action=staffeln&id={item.get('id','')}"
            _cm_fav = urllib.parse.urlencode({"action": "fav_add", "type": "serie",
                "url": _serie_params,
                "label": item.get("name", ""), "logo": item.get("poster", "")})
            li.addContextMenuItems([("Zu Kool-Fav hinzufuegen", f"RunPlugin({sys.argv[0]}?{_cm_fav})")])
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
        next_id = j.get("next", "")
        if next_id:
            li = xbmcgui.ListItem(label="Nächste Seite ▶")
            url_params = urllib.parse.urlencode({"action": "serien", "next": next_id})
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Serien nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

def show_serien_trending(next_id=None):
    show_serien(next_id=next_id or "series.trending")

def show_serien_popular(next_id=None):
    show_serien(next_id=next_id or "series.popular")

def show_serien_year():
    jahre = [str(y) for y in range(2025, 1999, -1)]
    idx = xbmcgui.Dialog().select("Jahr wählen", jahre)
    if idx == -1:
        xbmcplugin.endOfDirectory(HANDLE)
        return
    jahr = jahre[idx]
    show_serien(next_id=f"series.popular.year={jahr}")

def show_staffeln(series_id):
    url = f"https://www.kool.to/web-vod/api/info?id={series_id}"
    try:
        j = _kool_request(url)
        for season_nr in sorted(j.get("seasons", {}).keys(), key=lambda x: int(x)):
            label = f"Staffel {season_nr}" if season_nr != "0" else "Extras"
            li = xbmcgui.ListItem(label=label)
            url_params = urllib.parse.urlencode({"action": "episoden", "id": series_id, "season": season_nr})
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Staffeln nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

def show_episoden(series_id, season_nr):
    url = f"https://www.kool.to/web-vod/api/info?id={series_id}"
    try:
        j = _kool_request(url)
        episoden = j.get("seasons", {}).get(season_nr, [])
        for ep in episoden:
            label = f"Episode {ep.get('episode', '')} - {ep.get('name', '')}"
            li = xbmcgui.ListItem(label=label)
            li.setArt({"thumb": ep.get("poster", "")})
            li.setInfo("video", {"plot": ep.get("description", "")})
            url_params = urllib.parse.urlencode({
                "action": "hoster",
                "id": series_id,
                "season": season_nr,
                "episode": ep.get("episode", ""),
                "epid": ep.get("id", "")
            })
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Episoden nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

def show_hoster(series_id, season_nr, episode_nr, epid):
    url = f"https://www.kool.to/web-vod/api/links?id={epid}"
    try:
        hoster_list = _kool_request(url)
        for h in hoster_list:
            sName = h.get("name", "")
            hoster_url = h.get("url", "")
            li = xbmcgui.ListItem(label=sName)
            li.setProperty("IsPlayable", "true")
            url_params = urllib.parse.urlencode({
                "action": "play_hoster",
                "hoster_url": hoster_url
            })
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, False)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Hoster nicht holen:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

# Korrekte URLs – identisch mit verifiziertem Traffic der Lokke-App
_KOOL_CATALOG_URL = "https://www.kool.to/mediahubmx-catalog.json"
_KOOL_RESOLVE_URL = "https://www.kool.to/mediahubmx-resolve.json"

# Datei-Cache fuer Kanalliste (ueberlebt zwischen Kodi-Aufrufen)
_CHANNELS_CACHE_FILE = _xbmcvfs.translatePath(
    "special://userdata/addon_data/plugin.video.vodkool/channels_cache.json"
)
_CHANNELS_CACHE_TTL = 3600  # 1 Stunde

def _kool_live_request(url, body):
    """POST-Request mit mediahubmx-signature – Token wird dynamisch geholt."""
    token = _get_cached_token()
    if not token:
        raise Exception("Keine gueltige Signatur verfuegbar. Bitte Internetverbindung pruefen.")
    _h = {
        "content-type": "application/json; charset=utf-8",
        "user-agent": "MediaHubMX/2",
        "accept": "*/*",
        "Accept-Language": "de",
        "mediahubmx-signature": token,
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=_h)
    return json.loads(urllib.request.urlopen(req, timeout=15).read())


def _kool_live_geturl(channel_url):
    """Stream-URL aufloesen via mediahubmx-resolve.json."""
    resp = _kool_live_request(_KOOL_RESOLVE_URL, {
        "language": "de",
        "region": "AT",
        "url": channel_url,
    })
    return resp[0]["url"]


def _kool_live_fetch_channels():
    """Channel-Liste mit persistentem Datei-Cache (1 Stunde TTL).
    Jeder Kodi-Plugin-Aufruf ist ein neuer Prozess – daher Datei statt RAM-Cache."""
    # 1. Datei-Cache pruefen
    try:
        if _xbmcvfs.exists(_CHANNELS_CACHE_FILE):
            with _xbmcvfs.File(_CHANNELS_CACHE_FILE, "r") as f:
                cached = json.loads(f.read())
            if time.time() - cached.get("ts", 0) < _CHANNELS_CACHE_TTL:
                xbmc.log("[vodkool] Kanalliste aus Datei-Cache", xbmc.LOGINFO)
                return cached["groups"]
    except Exception as e:
        xbmc.log(f"[vodkool] Cache lesen fehlgeschlagen: {e}", xbmc.LOGWARNING)

    # 2. Frisch von API laden
    xbmc.log("[vodkool] Lade Kanalliste von API...", xbmc.LOGINFO)
    groups = {}
    cursor = 0
    while True:
        body = {
            "language": "de",
            "region": "AT",
            "catalogId": "iptv",
            "id": "iptv",
            "adult": False,
            "search": "",
            "sort": "",
            "filter": {"group": None},
            "cursor": cursor,
            "clientVersion": "3.0.3",
        }
        data = _kool_live_request(_KOOL_CATALOG_URL, body)
        for c in data.get("items", []):
            grp = c.get("group", "Other")
            if grp not in groups:
                groups[grp] = {}
            g = groups[grp]
            name = c.get("name", "")
            if name not in g:
                g[name] = []
            g[name].append(c)
        try:
            cursor = int(data["nextCursor"])
        except (KeyError, TypeError, ValueError):
            break

    # 3. In Datei speichern
    try:
        with _xbmcvfs.File(_CHANNELS_CACHE_FILE, "w") as f:
            f.write(json.dumps({"ts": time.time(), "groups": groups}))
        xbmc.log(f"[vodkool] Kanalliste gecacht: {len(groups)} Gruppen", xbmc.LOGINFO)
    except Exception as e:
        xbmc.log(f"[vodkool] Cache schreiben fehlgeschlagen: {e}", xbmc.LOGWARNING)

    return groups


def show_kool_live_countries():
    try:
        data = _kool_live_fetch_channels()
        if isinstance(data, dict):
            # Rokkr-Format: keys sind direkt die Gruppenname/Länder
            countries = {k: sum(len(v) for v in grp.values())
                         for k, grp in data.items()}
        else:
            # Flache Liste: country-Feld
            countries = {}
            for ch in data:
                c = ch.get("country", "Unbekannt")
                countries[c] = countries.get(c, 0) + 1
        for country in sorted(countries):
            li = xbmcgui.ListItem(label=f"{country} ({countries[country]})")
            url_params = urllib.parse.urlencode({"action": "kool_live_sort", "country": country})
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Länderliste nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)


def show_kool_live_sort(country):
    # Kein Fetch hier – nur statische Sortieroptionen anzeigen
    for label, sort in [("Trending", "trending"), ("Name", "name")]:
        li = xbmcgui.ListItem(label=label)
        url_params = urllib.parse.urlencode({"action": "kool_live_channels", "country": country, "sort": sort})
        xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    xbmcplugin.endOfDirectory(HANDLE)


def show_kool_live_channels(country, sort="trending"):
    try:
        data = _kool_live_fetch_channels()

        # /kool-iptv/ liefert ein Dict: {group: {name: [{url, name, logo}, ...]}}
        # Wir flachen das für das gewählte Land auf
        channels = []
        seen_urls = set()
        if isinstance(data, dict):
            # Rokkr-Format: groups dict
            group_data = data.get(country, {})
            for ch_name, streams in group_data.items():
                for s in streams:
                    u = s.get("url", "")
                    if not u or u in seen_urls:
                        continue
                    seen_urls.add(u)
                    lang = s.get("language") or s.get("languages") or ""
                    if isinstance(lang, list):
                        lang = ", ".join(lang)
                    channels.append({
                        "name": s.get("name", ch_name),
                        "url":  u,
                        "logo": s.get("logo", ""),
                        "lang": lang,
                    })
        else:
            # Fallback: flache Liste (altes /channels Format)
            channels = [c for c in data if c.get("country") == country]

        if sort == "name":
            channels.sort(key=lambda x: x.get("name", "").lower())

        for ch in channels:
            name   = ch.get("name", "")
            ch_url = ch.get("url", "")
            logo   = ch.get("logo", "")
            lang   = ch.get("lang", "")
            if not ch_url:
                continue
            display = f"{name}  [{lang}]" if lang else name
            li = xbmcgui.ListItem(label=display)
            if logo:
                li.setArt({"thumb": logo, "icon": logo})
            li.setProperty("IsPlayable", "true")
            url_params = urllib.parse.urlencode({
                "action": "play_kool_live",
                "url":    ch_url,
                "label":  name,
                "logo":   logo,
            })
            # Context-Menu: Zu Favoriten hinzufuegen
            cm_add = urllib.parse.urlencode({"action": "fav_add", "url": ch_url, "label": name, "logo": logo})
            li.addContextMenuItems([("Zu Favoriten hinzufuegen", f"RunPlugin({sys.argv[0]}?{cm_add})")])
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, False)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Senderliste nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)


def play_kool_live(channel_url, label="Live TV", logo=""):
    progress = xbmcgui.DialogProgress()
    progress.create("KOOL.TO", f"Starte {label}...")
    progress.update(20)
    try:
        stream_url = _kool_live_geturl(channel_url)
    except Exception as e:
        progress.close()
        xbmc.log(f"[vodkool] geturl failed: {e}", xbmc.LOGWARNING)
        show_error_dialog("Uuups!!!", f"Stream konnte nicht aufgelöst werden:\n{e}")
        return
    progress.update(60)
    xbmc.log(f"[vodkool] LiveTV stream: {stream_url[:80]}", xbmc.LOGINFO)
    progress.update(90)
    progress.close()
    # play_m3u8_stream übernimmt inputstream.ffmpegdirect + keep-alive korrekt
    from resources.lib.playhelper import play_m3u8_stream
    play_m3u8_stream(stream_url, label=label, thumb=logo if logo else None)


def show_iptv_countries():
    countries = [
        {"name": "Deutschland", "code": "de"},
        {"name": "Österreich", "code": "at"},
        {"name": "Schweiz", "code": "ch"},
        {"name": "Italien", "code": "it"},
        {"name": "Serbien", "code": "rs"},
        {"name": "Kroatien", "code": "hr"},
        {"name": "Bosnien & Herzegowina", "code": "ba"},
        {"name": "Montenegro", "code": "me"},
        {"name": "Mazedonien", "code": "mk"},
        {"name": "Albanien", "code": "al"},
        {"name": "Bulgarien", "code": "bg"},
        {"name": "Slowenien", "code": "si"},
        {"name": "Kosovo", "code": "xk"},
    ]
    for country in countries:
        li = xbmcgui.ListItem(country["name"])
        url_params = urllib.parse.urlencode({"action": "iptv_channels", "country": country["code"]})
        xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    xbmcplugin.endOfDirectory(HANDLE)

def show_iptv_channels(country_code):
    m3u_url = f"https://iptv-org.github.io/iptv/countries/{country_code}.m3u"
    cache_channels = []
    try:
        response = urllib.request.urlopen(m3u_url)
        playlist = response.read().decode("utf-8")
        entries = playlist.split("#EXTINF")
        for entry in entries[1:]:
            lines = entry.strip().splitlines()
            info = lines[0]
            url = lines[1] if len(lines) > 1 else None
            if not url or not url.startswith("http") or ".m3u8" not in url:
                continue
            name = info.split(",")[-1].strip() if "," in info else info.strip()
            logo = ""
            if "tvg-logo=" in info:
                logo = info.split('tvg-logo="')[1].split('"')[0]
            li = xbmcgui.ListItem(label=name)
            li.setProperty('IsPlayable', 'true')
            li.setProperty('inputstream', 'inputstream.adaptive')
            li.setMimeType('application/vnd.apple.mpegurl')
            li.setContentLookup(False)
            if logo:
                li.setArt({'thumb': logo, 'icon': logo, 'poster': logo})
            url_params = urllib.parse.urlencode({"action": "play_m3u8", "url": url, "label": name})
            _cm_fav = urllib.parse.urlencode({"action": "fav_add", "type": "iptv",
                "url": f"action=play_m3u8&url={urllib.parse.quote(url)}&label={urllib.parse.quote(name)}",
                "label": name, "logo": logo})
            li.addContextMenuItems([("Zu Kool-Fav hinzufuegen", f"RunPlugin({sys.argv[0]}?{_cm_fav})")])
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, False)
            cache_channels.append({"name": name, "url": url, "logo": logo, "country": country_code})
        # Suchcache aktualisieren (im Hintergrund)
        if cache_channels:
            _iptv_update_search_cache(country_code, cache_channels)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Senderliste fuer {country_code} nicht laden:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)

def _iptv_update_search_cache(country_code, channels):
    """Haengt neue Kanaele an den globalen IPTV-Suchcache an."""
    try:
        cache_file = _xbmcvfs.translatePath(
            "special://userdata/addon_data/plugin.video.vodkool/iptv_search_cache.json"
        )
        existing = []
        if _xbmcvfs.exists(cache_file):
            with _xbmcvfs.File(cache_file, "r") as f:
                existing = json.loads(f.read())
        # Vorhandene URLs fuer dieses Land entfernen, dann neu hinzufuegen
        existing = [c for c in existing if c.get("country") != country_code]
        existing.extend(channels)
        with _xbmcvfs.File(cache_file, "w") as f:
            f.write(json.dumps(existing, ensure_ascii=False))
    except Exception as e:
        xbmc.log(f"[vodkool] iptv cache update: {e}", xbmc.LOGWARNING)

def _suche_header(label):
    """Trennzeile als nicht-klickbarer Eintrag."""
    li = xbmcgui.ListItem(label=f"── {label} ──")
    xbmcplugin.addDirectoryItem(HANDLE, "", li, False)

def suche():
    text = xbmcgui.Dialog().input("Suchbegriff eingeben")
    if not text:
        xbmcplugin.endOfDirectory(HANDLE)
        return
    term = text.strip().lower()
    found_any = False

    # ── 1. kool.to Live TV (aus Datei-Cache oder API) ──
    try:
        groups = _kool_live_fetch_channels()
        live_hits = []
        seen_urls = set()
        for grp, channels in groups.items():
            for ch_name, streams in channels.items():
                if term in ch_name.lower():
                    for s in streams:
                        stream_url = s.get("url", "")
                        if not stream_url or stream_url in seen_urls:
                            continue
                        seen_urls.add(stream_url)
                        # Sprache/Land aus verfuegbaren Feldern lesen
                        lang = s.get("language") or s.get("languages") or ""
                        if isinstance(lang, list):
                            lang = ", ".join(lang)
                        country = s.get("country") or grp or ""
                        # Label: Name + Land + Sprache
                        display = s.get("name", ch_name)
                        meta_parts = [p for p in [country, lang] if p and p.lower() not in display.lower()]
                        if meta_parts:
                            display = f"{display}  [{', '.join(meta_parts)}]"
                        live_hits.append({
                            "name":    s.get("name", ch_name),
                            "display": display,
                            "url":     stream_url,
                            "logo":    s.get("logo", ""),
                        })
        if live_hits:
            _suche_header(f"kool.to Live TV ({len(live_hits)})")
            for ch in live_hits:
                li = xbmcgui.ListItem(label=ch["display"])
                if ch["logo"]:
                    li.setArt({"thumb": ch["logo"], "icon": ch["logo"]})
                li.setProperty("IsPlayable", "true")
                url_params = urllib.parse.urlencode({
                    "action": "play_kool_live",
                    "url":    ch["url"],
                    "label":  ch["name"],
                    "logo":   ch["logo"],
                })
                _cm = urllib.parse.urlencode({"action": "fav_add", "type": "live",
                    "url": ch["url"], "label": ch["name"], "logo": ch["logo"]})
                li.addContextMenuItems([("Zu Kool-Fav hinzufuegen",
                    f"RunPlugin({sys.argv[0]}?{_cm})")])
                xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, False)
                found_any = True
    except Exception as e:
        xbmc.log(f"[vodkool] Suche LiveTV: {e}", xbmc.LOGWARNING)

    # ── 2. Oeffentliche IPTV (iptv-org, nur wenn Cache vorhanden) ──
    try:
        iptv_cache_file = _xbmcvfs.translatePath(
            "special://userdata/addon_data/plugin.video.vodkool/iptv_search_cache.json"
        )
        iptv_channels = []
        if _xbmcvfs.exists(iptv_cache_file):
            with _xbmcvfs.File(iptv_cache_file, "r") as f:
                iptv_channels = json.loads(f.read())
        iptv_hits = [c for c in iptv_channels if term in c.get("name", "").lower()]
        if iptv_hits:
            _suche_header(f"Oeffentliche ({len(iptv_hits)})")
            for ch in iptv_hits:
                # Land zum Label hinzufuegen
                country_label = ch.get("country", "").upper()
                display_label = f"{ch['name']}  [{country_label}]" if country_label else ch["name"]
                li = xbmcgui.ListItem(label=display_label)
                li.setProperty("IsPlayable", "true")
                li.setMimeType("application/vnd.apple.mpegurl")
                li.setContentLookup(False)
                if ch.get("logo"):
                    li.setArt({"thumb": ch["logo"], "icon": ch["logo"]})
                url_params = urllib.parse.urlencode({"action": "play_m3u8",
                    "url": ch["url"], "label": ch["name"]})
                _cm = urllib.parse.urlencode({"action": "fav_add", "type": "iptv",
                    "url": f"action=play_m3u8&url={urllib.parse.quote(ch['url'])}&label={urllib.parse.quote(ch['name'])}",
                    "label": ch["name"], "logo": ch.get("logo", "")})
                li.addContextMenuItems([("Zu Kool-Fav hinzufuegen",
                    f"RunPlugin({sys.argv[0]}?{_cm})")])
                xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, False)
                found_any = True
    except Exception as e:
        xbmc.log(f"[vodkool] Suche IPTV: {e}", xbmc.LOGWARNING)

    # ── 3. kool.to VOD (Filme + Serien via API) ──
    try:
        vod_url = f"https://www.kool.to/web-vod/api/list?id=movie.popular.search={urllib.parse.quote_plus(text)}"
        j = _kool_request(vod_url)
        vod_items = j.get("data", [])
        if vod_items:
            _suche_header(f"Filme ({len(vod_items)})")
            for item in vod_items:
                li = xbmcgui.ListItem(label=item.get("name", ""))
                li.setArt({"thumb": item.get("poster", "")})
                li.setInfo("video", {"plot": item.get("description", "")})
                url_params = urllib.parse.urlencode({
                    "action": "hoster", "id": item.get("id", ""),
                    "season": "", "episode": "", "epid": item.get("id", "")
                })
                _vod_p = f"action=hoster&id={item.get('id','')}&season=&episode=&epid={item.get('id','')}"
                _cm = urllib.parse.urlencode({"action": "fav_add", "type": "vod",
                    "url": _vod_p, "label": item.get("name", ""), "logo": item.get("poster", "")})
                li.addContextMenuItems([("Zu Kool-Fav hinzufuegen",
                    f"RunPlugin({sys.argv[0]}?{_cm})")])
                xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
                found_any = True
        next_id = j.get("next", "")
        if next_id:
            li = xbmcgui.ListItem(label="Naechste Seite (Filme) ▶")
            url_params = urllib.parse.urlencode({"action": "suchen", "next": next_id, "search": text})
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        xbmc.log(f"[vodkool] Suche VOD: {e}", xbmc.LOGWARNING)

    # ── 4. kool.to Serien ──
    try:
        ser_url = f"https://www.kool.to/web-vod/api/list?id=series.popular.search={urllib.parse.quote_plus(text)}"
        js = _kool_request(ser_url)
        ser_items = js.get("data", [])
        if ser_items:
            _suche_header(f"Serien ({len(ser_items)})")
            for item in ser_items:
                li = xbmcgui.ListItem(label=item.get("name", ""))
                li.setArt({"thumb": item.get("poster", "")})
                li.setInfo("video", {"plot": item.get("description", "")})
                url_params = urllib.parse.urlencode({"action": "staffeln", "id": item.get("id", "")})
                _ser_p = f"action=staffeln&id={item.get('id','')}"
                _cm = urllib.parse.urlencode({"action": "fav_add", "type": "serie",
                    "url": _ser_p, "label": item.get("name", ""), "logo": item.get("poster", "")})
                li.addContextMenuItems([("Zu Kool-Fav hinzufuegen",
                    f"RunPlugin({sys.argv[0]}?{_cm})")])
                xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
                found_any = True
    except Exception as e:
        xbmc.log(f"[vodkool] Suche Serien: {e}", xbmc.LOGWARNING)

    if not found_any:
        li = xbmcgui.ListItem(label=f"Keine Ergebnisse fuer: {text}")
        xbmcplugin.addDirectoryItem(HANDLE, "", li, False)

    xbmcplugin.endOfDirectory(HANDLE)
    
def play_stream(api_url):
    data = _kool_request(api_url)
    hoster_url = data.get("url")
    if not hoster_url:
        show_error_dialog("Uuups!!!", "Keine Hoster-URL in API-Antwort gefunden!")
        return
    stream_url = resolver.resolve(hoster_url)
    if stream_url:
        li = xbmcgui.ListItem(path=stream_url)
        li.setProperty('IsPlayable', 'true')
        xbmcplugin.setResolvedUrl(HANDLE, True, li)
    else:
        show_error_dialog("Uuups!!!", "Kein Stream gefunden! (resolveurl konnte nicht auflösen)")    

def suche_paging(next_id=None, text=None):
    if not text:
        xbmcplugin.endOfDirectory(HANDLE)
        return
    url = f"https://www.kool.to/web-vod/api/list?id=movie.popular.search={urllib.parse.quote_plus(text)}"
    if next_id:
        url = f"https://www.kool.to/web-vod/api/list?id={next_id}"
    try:
        j = _kool_request(url)
        for item in j.get("data", []):
            li = xbmcgui.ListItem(label=item.get("name", ""))
            li.setArt({"thumb": item.get("poster", "")})
            li.setInfo("video", {"plot": item.get("description", "")})
            xbmcplugin.addDirectoryItem(HANDLE, "", li, False)
        next_id = j.get("next", "")
        if next_id:
            li = xbmcgui.ListItem(label="Nächste Seite ▶")
            url_params = urllib.parse.urlencode({"action": "suchen", "next": next_id, "search": text})
            xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    except Exception as e:
        show_error_dialog("Uuups!!!", f"Konnte Suche nicht ausführen:\n{e}")
    xbmcplugin.endOfDirectory(HANDLE)


# ═══════════════════════════════════════════════════════════
# FAVOURITEN
# ═══════════════════════════════════════════════════════════
_FAV_FILE = _xbmcvfs.translatePath(
    "special://userdata/addon_data/plugin.video.vodkool/favourites.json"
)

def _fav_load():
    try:
        if _xbmcvfs.exists(_FAV_FILE):
            with _xbmcvfs.File(_FAV_FILE, "r") as f:
                return json.loads(f.read())
    except Exception as e:
        xbmc.log(f"[vodkool] fav_load: {e}", xbmc.LOGWARNING)
    return []

def _fav_save(favs):
    try:
        with _xbmcvfs.File(_FAV_FILE, "w") as f:
            f.write(json.dumps(favs, ensure_ascii=False))
    except Exception as e:
        xbmc.log(f"[vodkool] fav_save: {e}", xbmc.LOGERROR)

def show_favourites():
    favs = _fav_load()
    if not favs:
        li = xbmcgui.ListItem(label="[Keine Kool-Fav Eintraege]")
        xbmcplugin.addDirectoryItem(HANDLE, "", li, False)
    for i, fav in enumerate(favs):
        li = xbmcgui.ListItem(label=fav.get("label", "?"))
        logo = fav.get("logo", "")
        if logo:
            li.setArt({"thumb": logo, "icon": logo, "poster": logo})
        fav_type = fav.get("type", "live")
        fav_url  = fav.get("url", "")
        # Live-Stream: direkt abspielen; VOD/Serie: als Ordner oeffnen
        if fav_type in ("live", "iptv"):
            li.setProperty("IsPlayable", "true")
            if fav_type == "live":
                target_url = f"{sys.argv[0]}?" + urllib.parse.urlencode({
                    "action": "play_kool_live",
                    "url":    fav_url,
                    "label":  fav.get("label", ""),
                    "logo":   logo,
                })
            else:
                # iptv: gespeicherte Router-Params direkt nutzen
                target_url = f"{sys.argv[0]}?{fav_url}"
            is_folder = False
        else:
            # VOD / Serie – gespeicherte Router-Params + aktuelles sys.argv[0]
            target_url = f"{sys.argv[0]}?{fav_url}"
            is_folder = True
        # Context-Menu: Umbenennen + Entfernen
        cm = []
        cm.append(("Umbenennen", f"RunPlugin({sys.argv[0]}?{urllib.parse.urlencode({'action':'fav_rename','idx':i,'label':fav.get('label','')})})"))
        cm.append(("Entfernen",  f"RunPlugin({sys.argv[0]}?{urllib.parse.urlencode({'action':'fav_remove','idx':i})})"))
        li.addContextMenuItems(cm)
        xbmcplugin.addDirectoryItem(HANDLE, target_url, li, is_folder)
    xbmcplugin.endOfDirectory(HANDLE)

def fav_add(url, label, logo="", fav_type="live"):
    favs = _fav_load()
    # Duplikate verhindern
    for f in favs:
        if f.get("url") == url:
            xbmcgui.Dialog().notification("Kool-Fav", f"{label} bereits vorhanden", xbmcgui.NOTIFICATION_INFO, 2500)
            return
    favs.append({"url": url, "label": label, "logo": logo, "type": fav_type})
    _fav_save(favs)
    xbmcgui.Dialog().notification("Kool-Fav", f"{label} hinzugefuegt", xbmcgui.NOTIFICATION_INFO, 2500)
    xbmc.executebuiltin("Container.Refresh")

def fav_remove(idx):
    favs = _fav_load()
    try:
        removed = favs.pop(int(idx))
        _fav_save(favs)
        xbmcgui.Dialog().notification("Kool-Fav", f"{removed.get('label','')} entfernt", xbmcgui.NOTIFICATION_INFO, 2500)
        xbmc.executebuiltin("Container.Refresh")
    except Exception as e:
        xbmc.log(f"[vodkool] fav_remove: {e}", xbmc.LOGWARNING)

def fav_rename(idx, old_label):
    new_label = xbmcgui.Dialog().input("Neuer Name", defaultt=old_label)
    if not new_label:
        return
    favs = _fav_load()
    try:
        favs[int(idx)]["label"] = new_label
        _fav_save(favs)
        xbmc.executebuiltin("Container.Refresh")
    except Exception as e:
        xbmc.log(f"[vodkool] fav_rename: {e}", xbmc.LOGWARNING)

def main_menu():
    menu_items = [
        ("Kool-Fav", "favourites"),
        ("kool.to Live TV", "kool_live_countries"),
        ("Öffentliche", "iptv_countries"),
        ("Filme Genre", "filme_filter"),          
        ("Angesagte Filme", "filme_trending"),
        ("Beliebte Filme", "filme_popular"),
        ("Angesagte Serien", "serien_trending"),
        ("Beliebte Serien", "serien_popular"),
        ("Nach Jahr", "filme_year"),
        ("Suchen", "suche"),
    ]
    for label, action in menu_items:
        li = xbmcgui.ListItem(label=label)
        url_params = urllib.parse.urlencode({"action": action})
        xbmcplugin.addDirectoryItem(HANDLE, f"{sys.argv[0]}?{url_params}", li, True)
    xbmcplugin.endOfDirectory(HANDLE)

# Router
try:
    if _action == "favourites":
        show_favourites()
    elif _action == "fav_add":
        fav_add(
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("url", "")),
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("label", "")),
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("logo", "")),
            dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("type", "live")
        )
    elif _action == "fav_remove":
        fav_remove(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("idx", "0"))
    elif _action == "fav_rename":
        fav_rename(
            dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("idx", "0"),
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("label", ""))
        )
    elif _action == "kool_live_countries":
        show_kool_live_countries()
    elif _action == "kool_live_sort":
        show_kool_live_sort(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("country", ""))
    elif _action == "kool_live_channels":
        show_kool_live_channels(
            dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("country", ""),
            dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("sort", "trending")
        )
    elif _action == "play_kool_live":
        play_kool_live(
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("url", "")),
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("label", "Live TV")),
            urllib.parse.unquote(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("logo", ""))
        )
    elif _action == "iptv_countries":
        show_iptv_countries()
    elif _action == "iptv_channels":
        show_iptv_channels(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("country", "de"))
    elif _action == "play_m3u8":
        # Placeholder für M3U8 Playback
        pass
    elif _action == "filme_filter":
        show_filme_filter()
    elif _action == "filme_trending":
        show_filme_trending(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("next"))
    elif _action == "filme_popular":
        show_filme_popular(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("next"))
    elif _action == "filme_genre":
        show_filme(catalog_id="movie.popular", genre=dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("genre", ""))
    elif _action == "filme_year":
        show_filme_year()
    elif _action == "filme":
        params = dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?")))
        show_filme(
            next_id=params.get("next"),
            genre=params.get("genre"),
            catalog_id=params.get("catalog", "movie.popular")
        )
    elif _action == "serien_trending":
        show_serien_trending(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("next"))
    elif _action == "serien_popular":
        show_serien_popular(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("next"))
    elif _action == "serien_year":
        show_serien_year()
    elif _action == "serien":
        show_serien(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("next"))
    elif _action == "staffeln":
        show_staffeln(dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?"))).get("id", ""))
    elif _action == "episoden":
        params = dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?")))
        show_episoden(params.get("id", ""), params.get("season", ""))
    elif _action == "hoster":
        params = dict(urllib.parse.parse_qsl(sys.argv[2].lstrip("?")))
        show_hoster(params.get("id", ""), params.get("season", ""), params.get("episode", ""), params.get("epid", ""))
    elif _action == "suchen":
        suche()
    else:
        main_menu()
except Exception as e:
    xbmc.log(f"[vodkool] HAUPTFEHLER: {e}", xbmc.LOGERROR)
    show_error_dialog("Fehler", f"Ein Fehler ist aufgetreten:\n{e}")
