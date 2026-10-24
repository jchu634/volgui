// Builds lightweight trees without loading complete artifact records.
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub id: i64,
    pub run_id: String,
    pub depth: usize,
    pub title: String,
    pub pid: Option<String>,
    pub ppid: Option<String>,
    pub path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegistryEntry {
    pub id: i64,
    pub hive: String,
    pub path: String,
    pub name: String,
    pub value_type: String,
}

#[derive(Clone, Debug)]
pub enum TreeNodeKind {
    Process,
    File,
    Directory,
    RegistryKey,
    RegistryValue,
}

#[derive(Clone, Debug)]
pub struct TreeNode {
    pub kind: TreeNodeKind,
    pub record_id: Option<i64>,
    pub label: String,
    pub pid: Option<String>,
    pub children: Vec<usize>,
    parent: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct ResultTree {
    pub nodes: Vec<TreeNode>,
    pub visible: Vec<(usize, usize)>,
    roots: Vec<usize>,
    collapsed: HashSet<usize>,
    included: HashSet<usize>,
}

impl ResultTree {
    pub fn processes(entries: Vec<TreeEntry>, matches: &[i64]) -> Self {
        let mut pids = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            if let Some(pid) = &entry.pid {
                pids.entry((entry.run_id.as_str(), pid.as_str()))
                    .or_insert(i);
            }
        }
        let mut tree = Self::default();
        let mut ancestors: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            let stack = ancestors.entry(&entry.run_id).or_default();
            stack.truncate(entry.depth);
            let parent = match entry.ppid.as_deref() {
                Some(ppid) => pids.get(&(entry.run_id.as_str(), ppid)).copied(),
                None => stack.last().copied(),
            }
            .filter(|parent| *parent != i);
            tree.nodes.push(TreeNode {
                kind: TreeNodeKind::Process,
                record_id: Some(entry.id),
                label: entry.title.clone(),
                pid: entry.pid.clone(),
                children: vec![],
                parent,
            });
            stack.push(i);
        }
        // Corrupt or reused PIDs can form cycles. Break each cycle into a root.
        let mut state = vec![0; tree.nodes.len()];
        for start in 0..tree.nodes.len() {
            let mut chain = vec![];
            let mut current = Some(start);
            while let Some(i) = current {
                if state[i] == 2 {
                    break;
                }
                if state[i] == 1 {
                    tree.nodes[i].parent = None;
                    break;
                }
                state[i] = 1;
                chain.push(i);
                current = tree.nodes[i].parent;
            }
            for i in chain {
                state[i] = 2;
            }
        }
        for i in 0..tree.nodes.len() {
            if let Some(parent) = tree.nodes[i].parent {
                tree.nodes[parent].children.push(i);
            } else {
                tree.roots.push(i);
            }
        }
        tree.filter(matches);
        tree
    }

    /// Handle runs must belong to the same evidence as the process entries.
    pub fn processes_with_files(
        entries: Vec<TreeEntry>,
        files: Vec<TreeEntry>,
        matches: &[i64],
    ) -> Self {
        let mut tree = Self::processes(entries, &[]);
        let mut processes: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, node) in tree.nodes.iter().enumerate() {
            if let Some(pid) = &node.pid {
                processes.entry(pid.clone()).or_default().push(i);
            }
        }
        let mut included = matches.to_vec();
        let matched: HashSet<_> = matches.iter().copied().collect();
        for file in files {
            let Some(parents) = file.pid.as_ref().and_then(|pid| processes.get(pid)) else {
                continue;
            };
            for parent in parents {
                if tree.nodes[*parent]
                    .record_id
                    .is_some_and(|id| matched.contains(&id))
                {
                    included.push(file.id);
                }
                tree.push_node(TreeNode {
                    kind: TreeNodeKind::File,
                    record_id: Some(file.id),
                    label: file
                        .path
                        .clone()
                        .filter(|p| !p.is_empty())
                        .unwrap_or_else(|| file.title.clone()),
                    pid: None,
                    children: vec![],
                    parent: Some(*parent),
                });
            }
        }
        // Keep a process's files visible before descending through its child processes.
        let file_nodes: HashSet<_> = tree
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, node)| matches!(node.kind, TreeNodeKind::File).then_some(i))
            .collect();
        for node in &mut tree.nodes {
            node.children
                .sort_by_key(|child| !file_nodes.contains(child));
        }
        tree.filter(&included);
        tree
    }

    pub fn files(entries: Vec<TreeEntry>, matches: &[i64]) -> Self {
        let mut tree = Self::default();
        let mut folders = HashMap::new();
        for entry in entries {
            let path = entry
                .path
                .as_deref()
                .filter(|p| !p.is_empty())
                .unwrap_or(&entry.title);
            let absolute = path.starts_with(['/', '\\']);
            let unc = path.starts_with("\\\\") || path.starts_with("//");
            let separator = if path.contains('\\') { '\\' } else { '/' };
            let mut parts: Vec<_> = path
                .split(['/', '\\'])
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
            if parts.is_empty() {
                parts.push("Unnamed file".into());
            }
            if absolute {
                let prefix = if unc {
                    "\\\\"
                } else if path.starts_with('/') {
                    "/"
                } else {
                    "\\"
                };
                parts[0] = format!("{prefix}{}", parts[0]);
            }
            let mut parent = None;
            for label in &parts[..parts.len() - 1] {
                let key = (parent, label.clone());
                let i = *folders.entry(key).or_insert_with(|| {
                    tree.push_node(TreeNode {
                        kind: TreeNodeKind::Directory,
                        record_id: None,
                        label: format!("{label}{separator}"),
                        pid: None,
                        children: vec![],
                        parent,
                    })
                });
                parent = Some(i);
            }
            tree.push_node(TreeNode {
                kind: TreeNodeKind::File,
                record_id: Some(entry.id),
                label: parts.pop().unwrap(),
                pid: None,
                children: vec![],
                parent,
            });
        }
        // Directories precede files, with stable ordering for duplicate records.
        let order = |a: &usize, b: &usize| {
            let a = &tree.nodes[*a];
            let b = &tree.nodes[*b];
            a.record_id
                .is_some()
                .cmp(&b.record_id.is_some())
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
                .then_with(|| a.record_id.cmp(&b.record_id))
        };
        let mut children: Vec<_> = tree.nodes.iter().map(|n| n.children.clone()).collect();
        for children in &mut children {
            children.sort_by(order);
        }
        tree.roots.sort_by(order);
        for (node, children) in tree.nodes.iter_mut().zip(children) {
            node.children = children;
        }
        tree.compact_folders();
        tree.filter(matches);
        tree
    }

    pub fn registry(entries: Vec<RegistryEntry>, matches: &[i64]) -> Self {
        let mut tree = Self::default();
        let mut keys = HashMap::new();
        for entry in entries {
            let mut parent = None;
            let components = std::iter::once(entry.hive.as_str())
                .chain(entry.path.split('\\').filter(|part| !part.is_empty()));
            for label in components {
                let key = (parent, label.to_lowercase());
                let i = *keys.entry(key).or_insert_with(|| {
                    tree.push_node(TreeNode {
                        kind: TreeNodeKind::RegistryKey,
                        record_id: None,
                        label: label.to_owned(),
                        pid: None,
                        children: vec![],
                        parent,
                    })
                });
                parent = Some(i);
            }
            if entry.value_type == "Hive" {
                if let Some(i) = parent {
                    if tree.nodes[i].record_id.is_none() {
                        tree.nodes[i].record_id = Some(entry.id);
                        if !entry.name.is_empty() {
                            tree.nodes[i].label = format!("{} - {}", entry.hive, entry.name);
                        }
                    } else {
                        tree.push_node(TreeNode {
                            kind: TreeNodeKind::RegistryKey,
                            record_id: Some(entry.id),
                            label: entry.name,
                            pid: None,
                            children: vec![],
                            parent,
                        });
                    }
                }
            } else if entry.value_type == "Key" {
                let key = (parent, entry.name.to_lowercase());
                let i = *keys.entry(key).or_insert_with(|| {
                    tree.push_node(TreeNode {
                        kind: TreeNodeKind::RegistryKey,
                        record_id: None,
                        label: entry.name.clone(),
                        pid: None,
                        children: vec![],
                        parent,
                    })
                });
                // Keep duplicate observations selectable without duplicating branches.
                if tree.nodes[i].record_id.is_none() {
                    tree.nodes[i].record_id = Some(entry.id);
                } else {
                    tree.push_node(TreeNode {
                        kind: TreeNodeKind::RegistryKey,
                        record_id: Some(entry.id),
                        label: entry.name,
                        pid: None,
                        children: vec![],
                        parent,
                    });
                }
            } else {
                let name = if entry.name.is_empty() {
                    "(Default)"
                } else {
                    &entry.name
                };
                tree.push_node(TreeNode {
                    kind: TreeNodeKind::RegistryValue,
                    record_id: Some(entry.id),
                    label: format!("{name} - {}", entry.value_type),
                    pid: None,
                    children: vec![],
                    parent,
                });
            }
        }
        tree.filter(matches);
        tree
    }

    fn compact_folders(&mut self) {
        let mut pending = self.roots.clone();
        while let Some(i) = pending.pop() {
            if self.nodes[i].record_id.is_some() {
                continue;
            }
            while self.nodes[i].children.len() == 1 {
                let child = self.nodes[i].children[0];
                if self.nodes[child].record_id.is_some() {
                    break;
                }
                let label = std::mem::take(&mut self.nodes[child].label);
                self.nodes[i].label.push_str(&label);
                let children = std::mem::take(&mut self.nodes[child].children);
                for child in &children {
                    self.nodes[*child].parent = Some(i);
                }
                self.nodes[i].children = children;
            }
            pending.extend(&self.nodes[i].children);
        }
    }

    fn push_node(&mut self, node: TreeNode) -> usize {
        let i = self.nodes.len();
        if let Some(parent) = node.parent {
            self.nodes[parent].children.push(i);
        } else {
            self.roots.push(i);
        }
        self.nodes.push(node);
        i
    }

    fn filter(&mut self, matches: &[i64]) {
        let matches: HashSet<_> = matches.iter().copied().collect();
        for i in 0..self.nodes.len() {
            if self.nodes[i]
                .record_id
                .is_some_and(|id| matches.contains(&id))
            {
                let mut current = Some(i);
                while let Some(i) = current {
                    if !self.included.insert(i) {
                        break;
                    }
                    current = self.nodes[i].parent;
                }
            }
        }
        self.refresh();
    }

    pub fn expanded(&self, i: usize) -> bool {
        !self.collapsed.contains(&i)
    }
    pub fn has_children(&self, i: usize) -> bool {
        self.nodes[i]
            .children
            .iter()
            .any(|child| self.included.contains(child))
    }

    pub fn toggle(&mut self, i: usize) {
        if !self.collapsed.remove(&i) {
            self.collapsed.insert(i);
        }
        self.refresh();
    }

    pub fn expand_all(&mut self, expand: bool) {
        self.collapsed = if expand {
            HashSet::new()
        } else {
            (0..self.nodes.len()).collect()
        };
        self.refresh();
    }

    fn refresh(&mut self) {
        self.visible.clear();
        let mut pending: Vec<_> = self.roots.iter().rev().map(|i| (*i, 0)).collect();
        while let Some((i, depth)) = pending.pop() {
            if !self.included.contains(&i) {
                continue;
            }
            self.visible.push((i, depth));
            if self.expanded(i) {
                pending.extend(
                    self.nodes[i]
                        .children
                        .iter()
                        .rev()
                        .map(|child| (*child, depth + 1)),
                );
            }
        }
    }
}
