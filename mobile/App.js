import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  AppState,
  FlatList,
  Keyboard,
  Modal,
  Pressable,
  RefreshControl,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const COLORS = {
  ink: '#182230', muted: '#7f8b9a', subtle: '#a1aab6', line: '#e8ecf1',
  canvas: '#f5f7fb', white: '#ffffff', navy: '#111b2a', blue: '#5968e8',
  green: '#25a976', red: '#d94f57', amber: '#d78228', yellow: '#b78a1d',
};
const API_STORAGE_KEY = '@vulnx/mobile-api-url';
const PAGE_SIZE = 20;
const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low', 'Unknown'];
const ENV_API_URL = process.env.EXPO_PUBLIC_API_URL || '';

function apiRoot(value) {
  const clean = value.trim().replace(/\/+$/, '');
  if (!clean) return '';
  return clean.endsWith('/api/v1') ? clean : `${clean}/api/v1`;
}

function severityFor(score) {
  if (score == null) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function dateLabel(value) {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : date.toLocaleDateString();
}

function cacheKey(root, search, severity, offset) {
  return `@vulnx/cache/${root}/${search}/${severity}/${offset}`;
}

export default function App() {
  const [serverUrl, setServerUrl] = useState(ENV_API_URL);
  const [serverDraft, setServerDraft] = useState(ENV_API_URL);
  const [storageReady, setStorageReady] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [summary, setSummary] = useState(null);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [severity, setSeverity] = useState('All');
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [refreshKey, setRefreshKey] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [online, setOnline] = useState(true);

  const root = useMemo(() => apiRoot(serverUrl), [serverUrl]);

  useEffect(() => {
    let mounted = true;
    AsyncStorage.getItem(API_STORAGE_KEY).then((savedUrl) => {
      if (mounted && !ENV_API_URL && savedUrl) {
        setServerUrl(savedUrl);
        setServerDraft(savedUrl);
      }
    }).catch(() => {}).finally(() => {
      if (mounted) setStorageReady(true);
    });
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    const timer = setInterval(() => setRefreshKey((value) => value + 1), 5 * 60 * 1000);
    const stateSubscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        setOnline(true);
        setRefreshKey((value) => value + 1);
      } else if (state === 'background' || state === 'inactive') {
        setOnline(false);
      }
    });
    return () => {
      clearInterval(timer);
      stateSubscription.remove();
    };
  }, []);

  useEffect(() => {
    if (!root) return undefined;
    let active = true;
    const listKey = cacheKey(root, debouncedQuery, severity, offset);

    async function load() {
      if (offset === 0) setLoading(true);
      else setLoadingMore(true);
      setError('');

      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
      if (debouncedQuery) params.set('search', debouncedQuery);
      if (severity !== 'All') params.set('severity', severity.toLowerCase());

      try {
        const [listResponse, summaryResponse] = await Promise.all([
          fetch(`${root}/vulns?${params.toString()}`),
          fetch(`${root}/summary`),
        ]);
        if (!listResponse.ok || !summaryResponse.ok) {
          throw new Error(`API returned ${!listResponse.ok ? listResponse.status : summaryResponse.status}`);
        }
        const listData = await listResponse.json();
        const summaryData = await summaryResponse.json();
        if (!active) return;
        setVulnerabilities((current) => {
          if (offset === 0) return listData.vulns || [];
          const seen = new Set(current.map((item) => item.cve_id));
          return [...current, ...(listData.vulns || []).filter((item) => !seen.has(item.cve_id))];
        });
        setTotal(listData.total || 0);
        setSummary(summaryData);
        await AsyncStorage.multiSet([
          [listKey, JSON.stringify(listData)],
          [`@vulnx/cache/${root}/summary`, JSON.stringify(summaryData)],
        ]);
        setOnline(true);
      } catch (requestError) {
        if (!active) return;
        setOnline(false);
        try {
          const [savedList, savedSummary] = await Promise.all([
            AsyncStorage.getItem(listKey),
            AsyncStorage.getItem(`@vulnx/cache/${root}/summary`),
          ]);
          if (savedList && active) {
            const cachedList = JSON.parse(savedList);
            setVulnerabilities((current) => offset === 0 ? cachedList.vulns || [] : current);
            setTotal(cachedList.total || 0);
          }
          if (savedSummary && active) setSummary(JSON.parse(savedSummary));
          setError(savedList ? 'Offline · showing saved vulnerability data.' : 'Can’t connect to the VulnX API. Check the server address and network.');
        } catch {
          setError(requestError.message || 'Could not load vulnerability data.');
        }
      } finally {
        if (active) {
          setLoading(false);
          setLoadingMore(false);
          setRefreshing(false);
        }
      }
    }

    load();
    return () => { active = false; };
  }, [root, debouncedQuery, severity, offset, refreshKey]);

  const saveServer = useCallback(async () => {
    Keyboard.dismiss();
    const nextRoot = apiRoot(serverDraft);
    try {
      const parsed = new URL(nextRoot);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Use an http or https address.');
    } catch {
      setError('Enter a full server address, for example http://192.168.1.20:8000');
      return;
    }
    const clean = serverDraft.trim().replace(/\/+$/, '');
    await AsyncStorage.setItem(API_STORAGE_KEY, clean);
    setServerUrl(clean);
    setOffset(0);
    setVulnerabilities([]);
    setError('');
    setShowSettings(false);
  }, [serverDraft]);

  const refresh = useCallback(() => {
    setRefreshing(true);
    setRefreshKey((value) => value + 1);
  }, []);

  const openDetails = useCallback(async (item) => {
    setSelected(item);
    setDetailLoading(true);
    try {
      const response = await fetch(`${root}/vulns/${encodeURIComponent(item.cve_id)}`);
      if (!response.ok) throw new Error('Could not load CVE details.');
      const data = await response.json();
      setSelected(data);
      await AsyncStorage.setItem(`@vulnx/cache/${root}/detail/${item.cve_id}`, JSON.stringify(data));
    } catch {
      const saved = await AsyncStorage.getItem(`@vulnx/cache/${root}/detail/${item.cve_id}`);
      if (saved) setSelected(JSON.parse(saved));
    } finally {
      setDetailLoading(false);
    }
  }, [root]);

  const loadMore = useCallback(() => {
    if (!loadingMore && !loading && vulnerabilities.length < total) setOffset((value) => value + PAGE_SIZE);
  }, [loadingMore, loading, vulnerabilities.length, total]);

  if (!storageReady) {
    return <SafeAreaView style={styles.loadingScreen}><StatusBar barStyle="light-content" backgroundColor={COLORS.navy} /><ActivityIndicator color={COLORS.blue} size="large" /></SafeAreaView>;
  }

  if (!root || showSettings) {
    return (
      <SafeAreaView style={styles.setupScreen}>
        <StatusBar barStyle="light-content" backgroundColor={COLORS.navy} />
        <View style={styles.setupBrand}><View style={styles.brandMark}><Text style={styles.brandMarkText}>V</Text></View><Text style={styles.brandName}>VulnX</Text></View>
        <Text style={styles.setupEyebrow}>STANDALONE MOBILE APP</Text>
        <Text style={styles.setupTitle}>{showSettings ? 'API connection' : 'Connect to your VulnX server'}</Text>
        <Text style={styles.setupBody}>Enter the address of the computer or hosted server running the VulnX API. On the same Wi-Fi, use your computer’s local IP address.</Text>
        <Text style={styles.fieldLabel}>SERVER ADDRESS</Text>
        <TextInput
          value={serverDraft}
          onChangeText={setServerDraft}
          placeholder="http://192.168.1.20:8000"
          placeholderTextColor="#718097"
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          returnKeyType="done"
          onSubmitEditing={saveServer}
          style={styles.serverInput}
        />
        {!!error && <Text style={styles.setupError}>{error}</Text>}
        <Pressable style={styles.primaryButton} onPress={saveServer}><Text style={styles.primaryButtonText}>Connect to VulnX</Text></Pressable>
        {showSettings && <Pressable style={styles.cancelButton} onPress={() => { setShowSettings(false); setServerDraft(serverUrl); setError(''); }}><Text style={styles.cancelButtonText}>Cancel</Text></Pressable>}
        <Text style={styles.setupFootnote}>The API must be reachable from this phone. For use outside your home network, use your hosted HTTPS API address.</Text>
      </SafeAreaView>
    );
  }

  const header = (
    <View>
      <View style={styles.hero}>
        <View style={styles.heroTop}>
          <View style={styles.brandInline}><View style={styles.brandMarkSmall}><Text style={styles.brandMarkTextSmall}>V</Text></View><Text style={styles.heroBrand}>VulnX</Text></View>
          <Pressable onPress={() => { setServerDraft(serverUrl); setShowSettings(true); setError(''); }} style={styles.settingsButton} accessibilityLabel="API settings"><Text style={styles.settingsButtonText}>⚙</Text></Pressable>
        </View>
        <Text style={styles.heroEyebrow}>THREAT INTELLIGENCE</Text>
        <Text style={styles.heroTitle}>Vulnerability{ '\n' }overview</Text>
        <View style={styles.connectionRow}><View style={[styles.connectionDot, !online && styles.connectionDotOffline]} /><Text style={styles.connectionText}>{online ? 'Connected to VulnX API' : 'Offline · saved data'}</Text></View>
      </View>

      <View style={styles.statsGrid}>
        <StatCard label="Tracked CVEs" value={summary?.total} tone="blue" />
        <StatCard label="Critical" value={summary?.critical} tone="red" />
        <StatCard label="High" value={summary?.high} tone="amber" />
      </View>

      <View style={styles.sectionHeading}><View><Text style={styles.sectionTitle}>Vulnerabilities</Text><Text style={styles.sectionSubtitle}>{total.toLocaleString()} records · CVSS priority</Text></View><Pressable onPress={refresh} style={styles.refreshButton}><Text style={styles.refreshButtonText}>↻</Text></Pressable></View>

      <View style={styles.searchWrap}><Text style={styles.searchIcon}>⌕</Text><TextInput value={query} onChangeText={setQuery} placeholder="Search CVE or description" placeholderTextColor={COLORS.subtle} style={styles.searchInput} returnKeyType="search" /></View>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.filters}>
        {SEVERITIES.map((item) => <Pressable key={item} onPress={() => { setSeverity(item); setOffset(0); }} style={[styles.filterChip, severity === item && styles.filterChipActive]}><Text style={[styles.filterText, severity === item && styles.filterTextActive]}>{item}</Text></Pressable>)}
      </ScrollView>
      {!!error && <View style={styles.notice}><Text style={styles.noticeText}>{error}</Text>{!online && <Text style={styles.noticeSubtext}>Data refreshes automatically when the app is active.</Text>}</View>}
    </View>
  );

  return (
    <SafeAreaView style={styles.appScreen}>
      <StatusBar barStyle="light-content" backgroundColor={COLORS.navy} />
      <FlatList
        data={vulnerabilities}
        keyExtractor={(item) => item.cve_id}
        renderItem={({ item }) => <VulnerabilityCard item={item} onPress={() => openDetails(item)} />}
        ListHeaderComponent={header}
        ListEmptyComponent={loading ? <View style={styles.empty}><ActivityIndicator color={COLORS.blue} /><Text style={styles.emptyText}>Loading vulnerabilities…</Text></View> : <Text style={styles.emptyText}>No vulnerabilities match these filters.</Text>}
        ListFooterComponent={loadingMore ? <ActivityIndicator style={styles.footerLoader} color={COLORS.blue} /> : vulnerabilities.length < total ? <Pressable onPress={loadMore} style={styles.loadMore}><Text style={styles.loadMoreText}>Load more vulnerabilities</Text></Pressable> : <Text style={styles.footerNote}>You’re all caught up</Text>}
        contentContainerStyle={styles.listContent}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={refresh} tintColor={COLORS.blue} colors={[COLORS.blue]} />}
        keyboardShouldPersistTaps="handled"
      />

      <Modal visible={!!selected} animationType="slide" presentationStyle="pageSheet" onRequestClose={() => setSelected(null)}>
        <SafeAreaView style={styles.detailScreen}>
          <View style={styles.detailTop}><Text style={styles.detailEyebrow}>VULNERABILITY DETAILS</Text><Pressable onPress={() => setSelected(null)} style={styles.closeButton}><Text style={styles.closeButtonText}>×</Text></Pressable></View>
          {selected && <ScrollView contentContainerStyle={styles.detailContent}>
            <Text style={styles.detailCve}>{selected.cve_id}</Text>
            <SeverityBadge severity={severityFor(selected.cvss_v3)} />
            <View style={styles.detailMetrics}><Text style={styles.detailMetric}>CVSS v3  <Text style={styles.detailMetricValue}>{selected.cvss_v3 == null ? 'N/A' : Number(selected.cvss_v3).toFixed(1)}</Text></Text><Text style={styles.detailMetric}>Published  <Text style={styles.detailMetricValue}>{dateLabel(selected.published_date)}</Text></Text></View>
            <Text style={styles.detailSectionTitle}>Description</Text>
            {detailLoading ? <ActivityIndicator color={COLORS.blue} /> : <Text style={styles.detailDescription}>{selected.description || 'No description provided by the source.'}</Text>}
            <Text style={styles.detailFooter}>Priority is normalized from CVSS v3 and is not a predictive model.</Text>
          </ScrollView>}
        </SafeAreaView>
      </Modal>
    </SafeAreaView>
  );
}

function StatCard({ label, value, tone }) {
  return <View style={styles.statCard}><View style={[styles.statDot, { backgroundColor: tone === 'red' ? COLORS.red : tone === 'amber' ? COLORS.amber : COLORS.blue }]} /><Text style={styles.statLabel}>{label}</Text><Text style={styles.statValue}>{value == null ? '—' : Number(value).toLocaleString()}</Text></View>;
}

function SeverityBadge({ severity }) {
  const tone = severity.toLowerCase();
  return (
    <View style={[styles.severityBadge, styles[`severity_${tone}`]]}>
      <View style={[styles.severityDot, styles[`severityDot_${tone}`]]} />
      <Text style={[styles.severityText, styles[`severityText_${tone}`]]}>{severity}</Text>
    </View>
  );
}

function VulnerabilityCard({ item, onPress }) {
  const severity = severityFor(item.cvss_v3);
  return (
    <Pressable onPress={onPress} style={({ pressed }) => [styles.vulnCard, pressed && styles.vulnCardPressed]}>
      <View style={styles.cardTop}><Text style={styles.cveId}>{item.cve_id}</Text><Text style={styles.cardArrow}>↗</Text></View>
      <Text style={styles.cveDescription} numberOfLines={2}>{item.description || 'No description provided by the source.'}</Text>
      <View style={styles.cardBottom}><SeverityBadge severity={severity} /><Text style={styles.cvssScore}>{item.cvss_v3 == null ? 'CVSS —' : `CVSS ${Number(item.cvss_v3).toFixed(1)}`}</Text><Text style={styles.cardDate}>{dateLabel(item.published_date)}</Text></View>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  loadingScreen: { flex: 1, backgroundColor: COLORS.navy, alignItems: 'center', justifyContent: 'center' },
  setupScreen: { flex: 1, backgroundColor: COLORS.navy, paddingHorizontal: 26, paddingTop: 35 },
  setupBrand: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 60 },
  brandMark: { width: 38, height: 38, borderRadius: 12, backgroundColor: '#5968e8', alignItems: 'center', justifyContent: 'center' },
  brandMarkText: { fontSize: 22, fontWeight: '800', color: COLORS.white },
  brandName: { color: COLORS.white, fontSize: 22, fontWeight: '800', letterSpacing: -0.8 },
  setupEyebrow: { color: '#9aa5ff', letterSpacing: 2, fontSize: 10, fontWeight: '800', marginBottom: 12 },
  setupTitle: { color: COLORS.white, fontSize: 29, lineHeight: 35, fontWeight: '800', letterSpacing: -0.8, marginBottom: 12 },
  setupBody: { color: '#abb6c7', fontSize: 14, lineHeight: 22, marginBottom: 26 },
  fieldLabel: { color: '#8793a7', fontSize: 10, fontWeight: '800', letterSpacing: 1.5, marginBottom: 8 },
  serverInput: { height: 50, backgroundColor: '#1d2a3c', borderWidth: 1, borderColor: '#344257', borderRadius: 10, paddingHorizontal: 14, color: COLORS.white, fontSize: 14 },
  primaryButton: { height: 50, backgroundColor: COLORS.blue, borderRadius: 10, alignItems: 'center', justifyContent: 'center', marginTop: 14 },
  primaryButtonText: { color: COLORS.white, fontSize: 14, fontWeight: '800' },
  cancelButton: { alignItems: 'center', padding: 15 },
  cancelButtonText: { color: '#abb6c7', fontSize: 13, fontWeight: '600' },
  setupError: { color: '#ff9898', fontSize: 12, marginTop: 9 },
  setupFootnote: { color: '#7f8da1', fontSize: 11, lineHeight: 18, marginTop: 23 },
  appScreen: { flex: 1, backgroundColor: COLORS.canvas },
  listContent: { paddingBottom: 24 },
  hero: { backgroundColor: COLORS.navy, paddingHorizontal: 22, paddingTop: 13, paddingBottom: 24, borderBottomLeftRadius: 22, borderBottomRightRadius: 22 },
  heroTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 23 },
  brandInline: { flexDirection: 'row', alignItems: 'center', gap: 9 },
  brandMarkSmall: { width: 29, height: 29, borderRadius: 9, backgroundColor: COLORS.blue, alignItems: 'center', justifyContent: 'center' },
  brandMarkTextSmall: { color: COLORS.white, fontWeight: '800', fontSize: 17 },
  heroBrand: { fontSize: 19, fontWeight: '800', color: COLORS.white, letterSpacing: -0.6 },
  settingsButton: { width: 36, height: 36, borderRadius: 11, backgroundColor: '#223148', alignItems: 'center', justifyContent: 'center' },
  settingsButtonText: { color: '#c4cce0', fontSize: 18 },
  heroEyebrow: { color: '#929eff', fontSize: 9, letterSpacing: 2, fontWeight: '800', marginBottom: 7 },
  heroTitle: { color: COLORS.white, fontSize: 30, lineHeight: 34, letterSpacing: -0.8, fontWeight: '800' },
  connectionRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginTop: 16 },
  connectionDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: '#36cf96' },
  connectionDotOffline: { backgroundColor: '#e1aa49' },
  connectionText: { color: '#a9b5c7', fontSize: 11 },
  statsGrid: { flexDirection: 'row', gap: 9, paddingHorizontal: 15, marginTop: -1 },
  statCard: { flex: 1, backgroundColor: COLORS.white, borderRadius: 12, borderWidth: 1, borderColor: COLORS.line, padding: 12, minHeight: 91 },
  statDot: { width: 7, height: 7, borderRadius: 4, marginBottom: 9 },
  statLabel: { color: COLORS.muted, fontSize: 10, fontWeight: '600' },
  statValue: { color: COLORS.ink, fontSize: 20, fontWeight: '800', marginTop: 3 },
  sectionHeading: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 19, marginTop: 24, marginBottom: 12 },
  sectionTitle: { color: COLORS.ink, fontSize: 17, fontWeight: '800', letterSpacing: -0.3 },
  sectionSubtitle: { color: COLORS.muted, fontSize: 10, marginTop: 4 },
  refreshButton: { width: 37, height: 37, backgroundColor: COLORS.white, borderWidth: 1, borderColor: COLORS.line, borderRadius: 11, alignItems: 'center', justifyContent: 'center' },
  refreshButtonText: { color: COLORS.blue, fontSize: 23, lineHeight: 27 },
  searchWrap: { flexDirection: 'row', alignItems: 'center', backgroundColor: COLORS.white, marginHorizontal: 15, height: 43, borderWidth: 1, borderColor: COLORS.line, borderRadius: 11, paddingHorizontal: 12 },
  searchIcon: { color: COLORS.muted, fontSize: 22, marginRight: 7 },
  searchInput: { flex: 1, color: COLORS.ink, fontSize: 13, paddingVertical: 0 },
  filters: { paddingHorizontal: 15, paddingTop: 12, paddingBottom: 5, gap: 7 },
  filterChip: { paddingHorizontal: 12, paddingVertical: 8, borderRadius: 18, backgroundColor: COLORS.white, borderWidth: 1, borderColor: COLORS.line },
  filterChipActive: { backgroundColor: COLORS.navy, borderColor: COLORS.navy },
  filterText: { color: '#667385', fontSize: 10, fontWeight: '700' },
  filterTextActive: { color: COLORS.white },
  notice: { backgroundColor: '#fff8e8', borderColor: '#f3e2b7', borderWidth: 1, marginHorizontal: 15, marginTop: 8, padding: 10, borderRadius: 9 },
  noticeText: { color: '#866b32', fontSize: 11 },
  noticeSubtext: { color: '#9b8658', fontSize: 10, marginTop: 4 },
  vulnCard: { backgroundColor: COLORS.white, borderColor: COLORS.line, borderWidth: 1, borderRadius: 13, marginHorizontal: 15, marginTop: 9, padding: 14 },
  vulnCardPressed: { opacity: 0.72 },
  cardTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  cveId: { color: '#5363dd', fontSize: 12, fontWeight: '800' },
  cardArrow: { color: '#a5afbc', fontSize: 16 },
  cveDescription: { color: '#738092', fontSize: 11, lineHeight: 17, marginTop: 8, marginBottom: 12 },
  cardBottom: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  severityBadge: { flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start', gap: 5, borderRadius: 12, paddingHorizontal: 8, paddingVertical: 5 },
  severityDot: { width: 5, height: 5, borderRadius: 3 },
  severityText: { fontSize: 9, fontWeight: '800' },
  severity_critical: { backgroundColor: '#fff0f0' }, severity_high: { backgroundColor: '#fff4e9' },
  severity_medium: { backgroundColor: '#fff9e7' }, severity_low: { backgroundColor: '#eaf8f1' }, severity_unknown: { backgroundColor: '#f0f2f5' },
  severityDot_critical: { backgroundColor: COLORS.red }, severityDot_high: { backgroundColor: COLORS.amber },
  severityDot_medium: { backgroundColor: COLORS.yellow }, severityDot_low: { backgroundColor: COLORS.green }, severityDot_unknown: { backgroundColor: COLORS.muted },
  severityText_critical: { color: COLORS.red }, severityText_high: { color: COLORS.amber },
  severityText_medium: { color: COLORS.yellow }, severityText_low: { color: COLORS.green }, severityText_unknown: { color: COLORS.muted },
  cvssScore: { color: '#536071', fontSize: 10, fontWeight: '700' },
  cardDate: { color: COLORS.subtle, fontSize: 9, marginLeft: 'auto' },
  empty: { paddingTop: 35, alignItems: 'center', gap: 10 },
  emptyText: { color: COLORS.muted, fontSize: 12, textAlign: 'center', padding: 28 },
  loadMore: { margin: 15, borderWidth: 1, borderColor: COLORS.line, borderRadius: 10, alignItems: 'center', padding: 13, backgroundColor: COLORS.white },
  loadMoreText: { color: COLORS.blue, fontSize: 12, fontWeight: '700' },
  footerLoader: { marginVertical: 20 },
  footerNote: { textAlign: 'center', color: COLORS.subtle, fontSize: 10, padding: 17 },
  detailScreen: { flex: 1, backgroundColor: COLORS.canvas },
  detailTop: { backgroundColor: COLORS.navy, paddingHorizontal: 20, paddingTop: 15, paddingBottom: 17, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  detailEyebrow: { color: '#9ba6ff', fontSize: 10, letterSpacing: 1.5, fontWeight: '800' },
  closeButton: { width: 32, height: 32, alignItems: 'center', justifyContent: 'center', backgroundColor: '#26354a', borderRadius: 10 },
  closeButtonText: { color: COLORS.white, fontSize: 24, lineHeight: 27 },
  detailContent: { padding: 21 },
  detailCve: { fontSize: 24, color: COLORS.ink, fontWeight: '800', marginBottom: 13 },
  detailMetrics: { flexDirection: 'row', flexWrap: 'wrap', gap: 15, borderBottomWidth: 1, borderBottomColor: COLORS.line, paddingVertical: 18, marginBottom: 18 },
  detailMetric: { color: COLORS.muted, fontSize: 11 },
  detailMetricValue: { color: COLORS.ink, fontWeight: '700' },
  detailSectionTitle: { color: COLORS.ink, fontSize: 13, fontWeight: '800', marginBottom: 8 },
  detailDescription: { color: '#647184', fontSize: 13, lineHeight: 22 },
  detailFooter: { color: COLORS.subtle, fontSize: 10, lineHeight: 16, marginTop: 26 },
});
