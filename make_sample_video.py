"""
Creates demo_phone_video.mp4: a 5-second test video carrying the same kind of
metadata a real phone records (GPS location, device make/model, recording time,
software). Use it to demonstrate the Video Metadata Sanitizer.

Usage:  python make_sample_video.py
"""
import shutil
import subprocess
import sys

ffmpeg = shutil.which("ffmpeg")
if not ffmpeg:
    sys.exit("ffmpeg not found on PATH. Install it first (see README).")

gps = "+28.6129+077.2295/"   # India Gate, New Delhi (fake location for the demo)
cmd = [
    ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
    "-f", "lavfi", "-i", "testsrc2=duration=5:size=640x360:rate=30",
    "-f", "lavfi", "-i", "sine=frequency=440:duration=5",
    "-metadata", "make=Apple",
    "-metadata", "model=iPhone 15 Pro",
    "-metadata", f"location={gps}",
    "-metadata", f"com.apple.quicktime.location.ISO6709={gps}",
    "-metadata", "com.apple.quicktime.make=Apple",
    "-metadata", "com.apple.quicktime.model=iPhone 15 Pro",
    "-metadata", "com.apple.quicktime.software=17.4.1",
    "-metadata", "creation_time=2026-08-15T09:30:00Z",
    "-metadata", "author=Student Name",
    "-metadata", "comment=Recorded near India Gate",
    "-movflags", "use_metadata_tags",
    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest",
    "demo_phone_video.mp4",
]
subprocess.run(cmd, check=True)
print("Created demo_phone_video.mp4 with fake GPS, device and time metadata.")
