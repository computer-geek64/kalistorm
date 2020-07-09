#!/usr/bin/python3
# music.py

import os
import youtube_dl


def get_youtube_music(url, directory):
    youtube_dl_options = {
    "format": "bestaudio/best",
    "postprocessors": [{
        "key": "FFmpegExtractAudio",
        "preferredcodec": "mp3"
    }],
    "nocheckcertificate": True,
    "outtmpl": os.path.join(directory, "%(title)s.%(ext)s")
    }
    try:
        with youtube_dl.YoutubeDL(youtube_dl_options) as ydl:
            ydl.download([url])
            return True
    except:
        return False
