import folium
from folium.plugins import MarkerCluster
import plotly.express as px

def generate_map(df):
    map = folium.Map(location=[20, 0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(map)
    
    for _, row in df.iterrows():
        folium.Marker(
            location=[row.get("latitude", 0), row.get("longitude", 0)],
            popup=f"IP: {row['source_ip']}<br>Threat: {row['threat_level']}",
        ).add_to(marker_cluster)
    
    return map._repr_html_()

def generate_frequency_plot(df):
    fig = px.bar(df, x="source_ip", y="request_count", color="threat_level")
    return fig.to_html(full_html=False)