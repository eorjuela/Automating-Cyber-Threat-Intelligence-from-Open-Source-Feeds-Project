"""
CTI Collection System - Streamlit Dashboard
Interactive visualization and analysis of collected threat intelligence
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, Any

# Page configuration
st.set_page_config(
    page_title="CTI Collection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    </style>
""", unsafe_allow_html=True)

@st.cache_data(ttl=60)  # Cache for 60 seconds
def load_data(db_path: str = "cti_thesis.db"):
    """Load all IoC data from database"""
    conn = sqlite3.connect(db_path)
    
    # Load IoCs
    df_iocs = pd.read_sql_query("""
        SELECT 
            indicator,
            type,
            source,
            first_seen,
            last_seen,
            seen_count,
            confidence,
            threat_level,
            metadata,
            created_at
        FROM iocs
        ORDER BY created_at DESC
    """, conn)
    
    # Load collection logs
    df_logs = pd.read_sql_query("""
        SELECT 
            source,
            collection_time,
            iocs_processed,
            iocs_new,
            iocs_updated,
            status,
            created_at
        FROM collection_logs
        ORDER BY created_at DESC
    """, conn)
    
    conn.close()
    
    # Convert date columns
    if not df_iocs.empty:
        df_iocs['first_seen'] = pd.to_datetime(df_iocs['first_seen'], errors='coerce')
        df_iocs['last_seen'] = pd.to_datetime(df_iocs['last_seen'], errors='coerce')
        df_iocs['created_at'] = pd.to_datetime(df_iocs['created_at'], errors='coerce')
    
    if not df_logs.empty:
        df_logs['collection_time'] = pd.to_datetime(df_logs['collection_time'], errors='coerce')
        df_logs['created_at'] = pd.to_datetime(df_logs['created_at'], errors='coerce')
    
    return df_iocs, df_logs

def get_statistics(df_iocs: pd.DataFrame) -> Dict[str, Any]:
    """Calculate key statistics"""
    if df_iocs.empty:
        return {
            'total_iocs': 0,
            'unique_indicators': 0,
            'by_type': {},
            'by_source': {},
            'by_threat_level': {},
            'by_confidence': {}
        }
    
    stats = {
        'total_iocs': len(df_iocs),
        'unique_indicators': df_iocs['indicator'].nunique(),
        'by_type': df_iocs['type'].value_counts().to_dict(),
        'by_source': df_iocs['source'].value_counts().to_dict(),
        'by_threat_level': df_iocs['threat_level'].value_counts().to_dict(),
        'by_confidence': df_iocs['confidence'].value_counts().to_dict(),
        'avg_seen_count': df_iocs['seen_count'].mean(),
        'max_seen_count': df_iocs['seen_count'].max()
    }
    
    return stats

def main():
    """Main dashboard function"""
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ CTI Collection System Dashboard</h1>', unsafe_allow_html=True)
    
    # Load data
    df_iocs, df_logs = load_data()
    
    if df_iocs.empty:
        st.warning("⚠️ No IoCs found in database. Run collection first using `python main.py single`")
        return
    
    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    
    # Search filter for specific IoC (placed first)
    search_term = st.sidebar.text_input(
        "Search by Indicator",
        placeholder="Enter IP, URL, hash, domain, etc.",
        help="Search for specific IoCs by indicator value (case-insensitive)"
    )
    
    # Type filter
    types = ['All'] + sorted(df_iocs['type'].unique().tolist())
    selected_type = st.sidebar.selectbox("IoC Type", types)
    
    # Source filter
    sources = ['All'] + sorted(df_iocs['source'].unique().tolist())
    selected_source = st.sidebar.selectbox("Source", sources)
    
    # Threat level filter
    threat_levels = ['All'] + sorted(df_iocs['threat_level'].unique().tolist())
    selected_threat = st.sidebar.selectbox("Threat Level", threat_levels)
    
    # Confidence filter
    confidences = ['All'] + sorted(df_iocs['confidence'].unique().tolist())
    selected_confidence = st.sidebar.selectbox("Confidence", confidences)
    
    # Date range filter
    st.sidebar.subheader("Date Range")
    min_date = df_iocs['first_seen'].min().date() if not df_iocs.empty else datetime.now().date()
    max_date = df_iocs['first_seen'].max().date() if not df_iocs.empty else datetime.now().date()
    
    date_range = st.sidebar.date_input(
        "Select Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    # Apply filters
    filtered_df = df_iocs.copy()
    
    # Apply search filter
    if search_term and search_term.strip():
        search_term = search_term.strip()
        filtered_df = filtered_df[
            filtered_df['indicator'].str.contains(search_term, case=False, na=False)
        ]
    
    if selected_type != 'All':
        filtered_df = filtered_df[filtered_df['type'] == selected_type]
    
    if selected_source != 'All':
        filtered_df = filtered_df[filtered_df['source'] == selected_source]
    
    if selected_threat != 'All':
        filtered_df = filtered_df[filtered_df['threat_level'] == selected_threat]
    
    if selected_confidence != 'All':
        filtered_df = filtered_df[filtered_df['confidence'] == selected_confidence]
    
    if isinstance(date_range, tuple) and len(date_range) == 2:
        filtered_df = filtered_df[
            (filtered_df['first_seen'].dt.date >= date_range[0]) &
            (filtered_df['first_seen'].dt.date <= date_range[1])
        ]
    
    # Show search results info
    if search_term and search_term.strip():
        search_count = len(filtered_df)
        total_count = len(df_iocs)
        st.info(f"Search Results: Found **{search_count:,}** IoC(s) matching '{search_term}' out of {total_count:,} total IoCs")
    
    # Key Metrics
    stats = get_statistics(filtered_df)
    
    st.header("📊 Key Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total IoCs", f"{stats['total_iocs']:,}")
    
    with col2:
        st.metric("Unique Indicators", f"{stats['unique_indicators']:,}")
    
    with col3:
        st.metric("Avg Seen Count", f"{stats['avg_seen_count']:.2f}")
    
    with col4:
        st.metric("Max Seen Count", f"{stats['max_seen_count']:.0f}")
    
    # Charts Row 1
    st.header("📈 Trend Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        # IoCs Over Time
        if not filtered_df.empty:
            daily_counts = filtered_df.groupby(filtered_df['first_seen'].dt.date).size().reset_index()
            daily_counts.columns = ['Date', 'Count']
            
            fig_trend = px.line(
                daily_counts,
                x='Date',
                y='Count',
                title='IoCs Collected Over Time',
                labels={'Count': 'Number of IoCs', 'Date': 'Date'},
                markers=True
            )
            fig_trend.update_layout(height=400)
            st.plotly_chart(fig_trend, use_container_width=True)
        else:
            st.info("No data available for selected filters")
    
    with col2:
        # IoCs by Type
        if stats['by_type']:
            fig_type = px.pie(
                values=list(stats['by_type'].values()),
                names=list(stats['by_type'].keys()),
                title='IoCs by Type'
            )
            fig_type.update_layout(height=400)
            st.plotly_chart(fig_type, use_container_width=True)
        else:
            st.info("No data available")
    
    # Charts Row 2
    col1, col2 = st.columns(2)
    
    with col1:
        # IoCs by Source
        if stats['by_source']:
            fig_source = px.bar(
                x=list(stats['by_source'].keys()),
                y=list(stats['by_source'].values()),
                title='IoCs by Source',
                labels={'x': 'Source', 'y': 'Count'}
            )
            fig_source.update_layout(height=400)
            st.plotly_chart(fig_source, use_container_width=True)
        else:
            st.info("No data available")
    
    with col2:
        # Threat Level Distribution
        if stats['by_threat_level']:
            fig_threat = px.bar(
                x=list(stats['by_threat_level'].keys()),
                y=list(stats['by_threat_level'].values()),
                title='Threat Level Distribution',
                labels={'x': 'Threat Level', 'y': 'Count'},
                color=list(stats['by_threat_level'].keys()),
                color_discrete_map={'high': 'red', 'medium': 'orange', 'low': 'green'}
            )
            fig_threat.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig_threat, use_container_width=True)
        else:
            st.info("No data available")
    
    # Top IoCs Table
    st.header("🔝 Top IoCs")
    
    # Sort options
    sort_by = st.selectbox(
        "Sort by",
        ["Seen Count (Most)", "Seen Count (Least)", "Most Recent", "Oldest"],
        key="sort_select"
    )
    
    if sort_by == "Seen Count (Most)":
        top_iocs = filtered_df.nlargest(20, 'seen_count')
    elif sort_by == "Seen Count (Least)":
        top_iocs = filtered_df.nsmallest(20, 'seen_count')
    elif sort_by == "Most Recent":
        top_iocs = filtered_df.nlargest(20, 'first_seen')
    else:
        top_iocs = filtered_df.nsmallest(20, 'first_seen')
    
    # Display table
    display_cols = ['indicator', 'type', 'source', 'seen_count', 'threat_level', 'confidence', 'first_seen']
    st.dataframe(
        top_iocs[display_cols].rename(columns={
            'indicator': 'Indicator',
            'type': 'Type',
            'source': 'Source',
            'seen_count': 'Seen Count',
            'threat_level': 'Threat Level',
            'confidence': 'Confidence',
            'first_seen': 'First Seen'
        }),
        use_container_width=True,
        height=400
    )
    
    # Export Section
    st.header("💾 Export Data")
    col1, col2 = st.columns(2)
    
    with col1:
        # CSV Export
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download as CSV",
            data=csv,
            file_name=f"cti_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col2:
        # JSON Export
        json_data = filtered_df.to_json(orient='records', date_format='iso')
        st.download_button(
            label="Download as JSON",
            data=json_data,
            file_name=f"cti_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    # Collection Logs
    if not df_logs.empty:
        st.header("📋 Collection Logs")
        
        # Summary stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Collections", len(df_logs))
        with col2:
            successful = len(df_logs[df_logs['status'] == 'success'])
            st.metric("Successful", successful)
        with col3:
            failed = len(df_logs[df_logs['status'] == 'error'])
            st.metric("Failed", failed)
        
        # Recent collections chart
        if len(df_logs) > 0:
            logs_daily = df_logs.groupby(df_logs['created_at'].dt.date).agg({
                'iocs_new': 'sum',
                'iocs_processed': 'sum'
            }).reset_index()
            
            fig_logs = go.Figure()
            fig_logs.add_trace(go.Scatter(
                x=logs_daily['created_at'],
                y=logs_daily['iocs_new'],
                name='New IoCs',
                mode='lines+markers'
            ))
            fig_logs.add_trace(go.Scatter(
                x=logs_daily['created_at'],
                y=logs_daily['iocs_processed'],
                name='Processed IoCs',
                mode='lines+markers'
            ))
            fig_logs.update_layout(
                title='Collection Activity Over Time',
                xaxis_title='Date',
                yaxis_title='Count',
                height=400
            )
            st.plotly_chart(fig_logs, use_container_width=True)
        
        # Recent logs table
        st.subheader("Recent Collection Runs")
        st.dataframe(
            df_logs.head(20)[['source', 'collection_time', 'iocs_processed', 'iocs_new', 'iocs_updated', 'status']].rename(columns={
                'source': 'Source',
                'collection_time': 'Collection Time',
                'iocs_processed': 'Processed',
                'iocs_new': 'New',
                'iocs_updated': 'Updated',
                'status': 'Status'
            }),
            use_container_width=True
        )
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>CTI Collection System Dashboard | Last updated: " + 
        datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()

