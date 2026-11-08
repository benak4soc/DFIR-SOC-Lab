"""Country coordinates and travel-speed checks for the impossible-travel use case."""

from math import asin, cos, radians, sin, sqrt

# Representative coordinates for the lab countries. They are not a GeoIP database.
COUNTRY_COORDS = {
    "DE": (52.520, 13.405),
    "FR": (48.857, 2.351),
    "GB": (51.507, -0.128),
    "US": (38.907, -77.037),
    "BR": (-15.797, -47.891),
    "NG": (6.455, 3.384),
    "JP": (35.682, 139.759),
}

EARTH_KM = 6371.0


def haversine_km(origin, destination):
    lat1, lon1 = (radians(value) for value in origin)
    lat2, lon2 = (radians(value) for value in destination)
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    chord = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 2 * EARTH_KM * asin(sqrt(chord))


def travel_speed_kmh(origin_country, destination_country, elapsed_seconds):
    origin = COUNTRY_COORDS[origin_country]
    destination = COUNTRY_COORDS[destination_country]
    hours = max(elapsed_seconds, 1) / 3600
    return haversine_km(origin, destination) / hours
