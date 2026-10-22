#!/usr/bin/env python3
"""Génère les objets du tableau de bord « Équipements réseau » (NDJSON pour
l'API saved_objects du dashboard Wazuh / OpenSearch Dashboards).

Objets créés (index pattern Wazuh « wazuh-alerts-* ») :
  - recherches enregistrées par catégorie (colonnes device.* prêtes à l'emploi)
  - visualisations : catégories, équipements, constructeurs, sites, évolution,
    principales règles, échecs d'authentification par équipement
  - tableau de bord « Équipements réseau (SOC) »
Usage : build_network_dashboard.py > objets.ndjson
"""
import json
import sys

IP = "wazuh-alerts-*"
PREFIX = "wzp-net-"
BASE_FILTER = "device.category:*"


def ref():
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": IP}]


def search_source(query):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})


def saved_search(oid, title, query):
    return {"id": PREFIX + oid, "type": "search", "references": ref(),
            "attributes": {"title": title, "description": "", "hits": 0,
                           "columns": ["device.name", "device.category", "device.site", "rule.description",
                                       "rule.level", "data.srcip"],
                           "sort": [["timestamp", "desc"]],
                           "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}}}


def terms(field, size=10, schema="segment", label=None):
    params = {"field": field, "size": size, "order": "desc", "orderBy": "1", "otherBucket": False,
              "missingBucket": False}
    if label:
        params["customLabel"] = label
    return {"id": schema + field, "enabled": True, "type": "terms", "schema": schema, "params": params}


COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}}


def vis(oid, title, vtype, aggs, params, query=BASE_FILTER):
    state = {"title": title, "type": vtype, "aggs": [COUNT] + aggs, "params": params}
    return {"id": PREFIX + oid, "type": "visualization", "references": ref(),
            "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}",
                           "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}}}


PIE = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True,
       "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}
TABLE = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
         "totalFunc": "sum", "percentageCol": ""}


def hbar():
    return {"type": "histogram", "grid": {"categoryLines": False}, "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "times": [], "addTimeMarker": False,
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left", "show": True,
                              "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": False,
                                                                                   "truncate": 200},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "bottom",
                           "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                           "title": {"text": "Alertes"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Alertes", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}]}


def area():
    return {"type": "area", "grid": {"categoryLines": False}, "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "times": [], "addTimeMarker": False,
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                              "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                           "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Alertes"}}],
            "seriesParams": [{"show": True, "type": "area", "mode": "stacked",
                              "data": {"label": "Alertes", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True, "interpolate": "linear"}]}


DATE = {"id": "date", "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}}

objs = [
    saved_search("all", "Équipements réseau — toutes les alertes", BASE_FILTER),
    saved_search("firewall", "Équipements réseau — Pare-feu", 'device.type:"firewall"'),
    saved_search("routing", "Équipements réseau — Routeurs et switches", 'device.type:("router" or "switch")'),
    saved_search("high", "Équipements réseau — alertes niveau ≥ 10", BASE_FILTER + " and rule.level >= 10"),
    vis("cat", "Équipements — alertes par catégorie", "pie", [terms("device.category")], PIE),
    vis("dev", "Équipements — alertes par équipement", "histogram",
        [terms("device.name", 15), terms("device.category", 5, "group")], hbar()),
    vis("vendor", "Équipements — alertes par constructeur", "pie", [terms("device.vendor")], PIE),
    vis("site", "Équipements — alertes par site", "pie", [terms("device.site")], PIE),
    vis("time", "Équipements — évolution par catégorie", "area", [DATE, terms("device.category", 6, "group")],
        area()),
    vis("rules", "Équipements — principales règles déclenchées", "table",
        [terms("device.name", 20, "bucket", "Équipement"), terms("rule.description", 5, "bucket", "Règle"),
         terms("rule.level", 1, "bucket", "Niveau")], TABLE),
    vis("auth", "Équipements — échecs d'authentification par équipement", "histogram",
        [terms("device.name", 15), terms("data.srcip", 5, "group")], hbar(),
        BASE_FILTER + " and rule.groups:(authentication_failed or authentication_failures)"),
]

panels, refs = [], []
layout = [("cat", 0, 0, 16, 14), ("vendor", 16, 0, 16, 14), ("site", 32, 0, 16, 14),
          ("time", 0, 14, 48, 12), ("dev", 0, 26, 24, 16), ("auth", 24, 26, 24, 16), ("rules", 0, 42, 48, 18)]
for i, (oid, x, y, w, h) in enumerate(layout):
    panels.append({"version": "2.19.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                   "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
    refs.append({"name": f"panel_{i}", "type": "visualization", "id": PREFIX + oid})
panels.append({"version": "2.19.0", "gridData": {"x": 0, "y": 60, "w": 48, "h": 18, "i": "99"},
               "panelIndex": "99", "embeddableConfig": {}, "panelRefName": f"panel_{len(layout)}"})
refs.append({"name": f"panel_{len(layout)}", "type": "search", "id": PREFIX + "all"})

objs.append({"id": PREFIX + "dashboard", "type": "dashboard", "references": refs,
             "attributes": {"title": "Équipements réseau (SOC)",
                            "description": "Alertes des pare-feu, routeurs et switches classées par catégorie, "
                                           "équipement, constructeur et site (champs device.*).",
                            "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"hidePanelTitles": False,
                                                                                         "useMargins": True}),
                            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
                            "refreshInterval": {"pause": False, "value": 60000},
                            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                {"query": {"query": "", "language": "kuery"}, "filter": []})}}})

for o in objs:
    sys.stdout.write(json.dumps(o, ensure_ascii=False) + "\n")
