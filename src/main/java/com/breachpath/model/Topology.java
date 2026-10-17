package com.breachpath.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The enterprise network: assets plus the connections between them. */
public class Topology {
    private final List<Asset> assets;
    private final List<Link> links;
    private final Map<String, Integer> index = new HashMap<>();

    public Topology(List<Asset> assets, List<Link> links) {
        this.assets = List.copyOf(assets);
        this.links = List.copyOf(links);
        for (int i = 0; i < this.assets.size(); i++) {
            index.put(this.assets.get(i).name(), i);
        }
    }

    public int size() {
        return assets.size();
    }

    public Asset asset(int i) {
        return assets.get(i);
    }

    public List<Asset> assets() {
        return assets;
    }

    public List<Link> links() {
        return links;
    }

    public boolean has(String name) {
        return index.containsKey(name);
    }

    public int indexOf(String name) {
        Integer i = index.get(name);
        if (i == null) {
            throw new IllegalArgumentException("Unknown asset: " + name);
        }
        return i;
    }
}
