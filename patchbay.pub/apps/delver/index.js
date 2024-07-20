const RemFSDelver = (options) => {
  const dom = document.createElement('div');
  dom.classList.add('remfs-delver');

  const urlParams = new URLSearchParams(window.location.search);

  let curDir;
  let curPath;
  let remfsRoot;
  let layout = 'list';

  let rootUrl;
  if (urlParams.has('remfs-root')) {
    rootUrl = urlParams.get('remfs-root');
  }
  else if (options && options.rootUrl) {
    rootUrl = options.rootUrl;
  }

  if (!rootUrl) {
    dom.innerText = "Error: No remfs-root provided";
    return dom;
  }

  // TODO: re-enable control bar once it does something useful.
  //const controlBar = ControlBar();
  //dom.appendChild(controlBar.dom);

  const dirContainer = document.createElement('div');
  dirContainer.classList.add('remfs-delver__dir-container');
  dom.appendChild(dirContainer);


  fetch(rootUrl + '/remfs.json')
  .then(response => response.json())
  .then(remfs => {
    remfsRoot = remfs;
    curDir = remfsRoot;
    curPath = [];

    dirContainer.appendChild(Directory(remfsRoot, curDir, rootUrl, curPath, layout));

    //controlBar.dom.addEventListener('layout-list', (e) => {
    //  layout = 'list';
    //  updateDirEl();
    //});

    //controlBar.dom.addEventListener('layout-grid', (e) => {
    //  layout = 'grid';
    //  updateDirEl();
    //});
  });

  dirContainer.addEventListener('change-dir', (e) => {
    curDir = remfsRoot;
    curPath = e.detail.path;
    for (const part of curPath) {
      curDir = curDir.children[part];
    }

    if (curDir.children) {
      updateDirEl();
    }
    else {
      fetch(rootUrl + encodePath(curPath) + '/remfs.json')
      .then(response => response.json())
      .then(remfs => {
        curDir.children = remfs.children;
        updateDirEl();
      });
    }
  });

  function updateDirEl() {
    const newDirEl = Directory(remfsRoot, curDir, rootUrl, curPath, layout)
    dirContainer.replaceChild(newDirEl, dirContainer.childNodes[0]);
  }

  return dom;
};

const ControlBar = () => {
  const dom = document.createElement('div');
  dom.classList.add('remfs-delver__control-bar');

  const listIconEl = document.createElement('ion-icon');
  listIconEl.name = 'list';
  listIconEl.addEventListener('click', (e) => {
    dom.dispatchEvent(new CustomEvent('layout-list', {
      bubbles: true,
    }));
  });
  dom.appendChild(listIconEl);
  
  const gridIconEl = document.createElement('ion-icon');
  gridIconEl.name = 'apps';
  gridIconEl.addEventListener('click', (e) => {
    dom.dispatchEvent(new CustomEvent('layout-grid', {
      bubbles: true,
    }));
  });
  dom.appendChild(gridIconEl);

  return { dom };
};

const Directory = (root, dir, rootUrl, path, layout) => {
  const dom = document.createElement('div');
  dom.classList.add('remfs-delver__directory');

  if (path.length > 0) {
    const parentPath = path.slice();
    parentPath.pop();
    const parentPlaceholder = {
      type: 'dir',
    };
    const upDir = ListItem(root, '..', parentPlaceholder, rootUrl, parentPath);
    dom.appendChild(upDir);
  }

  if (dir.children) {
    for (const filename in dir.children) {
      const child = dir.children[filename];
      const childPath = path.concat(filename);
      const childEl = ListItem(root, filename, child, rootUrl, childPath)
      dom.appendChild(childEl);

      // TODO: This currently isn't being used, but probably should be
      // eventually for performance. It's now defaulting to getting the
      // entire tree on first load.
      //if (child.type === 'dir') {
      //  // greedily get all children 1 level down.
      //  if (!child.children) {
      //    fetch(rootUrl + encodePath(childPath) + '/remfs.json')
      //    .then(response => response.json())
      //    .then(remfs => {
      //      child.children = remfs.children;
      //    });
      //  }
      //}
    }
  }

  return dom;
};

const ListItem = (root, filename, item, rootUrl, path) => {
  const dom = document.createElement('a');
  dom.classList.add('remfs-delver__list-item');
  dom.setAttribute('href', rootUrl + encodePath(path));

  const inner = document.createElement('div');
  inner.classList.add('remfs-delver__list-content');

  if (item.type === 'dir') {
    const iconEl = document.createElement('ion-icon');
    iconEl.name = 'folder';
    inner.appendChild(iconEl);
  }
  else {
    let thumb = false;
    if (isImage(filename) && root.children.thumbnails) {
      let curThumbItem = root.children.thumbnails;

      for (const part of path) {
        if (curThumbItem.children) {
          curThumbItem = curThumbItem.children[part];
        }
        else {
          console.log("thumb not found");
          break;
        }
      }

      if (curThumbItem) {
        thumb = true;
      }
    }

    if (thumb) {
      const thumbEl = document.createElement('img');
      thumbEl.classList.add('remfs-delver__thumb');

      thumbEl.src = rootUrl + '/thumbnails' + encodePath(path);
      inner.appendChild(thumbEl);
    }
    else {
      const iconEl = document.createElement('ion-icon');
      iconEl.name = 'document';
      inner.appendChild(iconEl);
    }
  }

  const filenameEl = document.createElement('span');
  filenameEl.classList.add('remfs-delver__list-item-filename');
  filenameEl.innerText = filename;
  inner.appendChild(filenameEl);

  dom.addEventListener('click', (e) => {

    if (item.type === 'dir') {
      e.preventDefault();
      dom.dispatchEvent(new CustomEvent('change-dir', {
        bubbles: true,
        detail: {
          path,
        },
      }));
    }
    else {
      dom.setAttribute('target', '_blank');
    }
  });

  dom.appendChild(inner);

  return dom;
};

function encodePath(parts) {
  return '/' + parts.join('/');
}

function parsePath(pathStr) {
  return pathStr.split('/').slice(1);
}

function isImage(pathStr) {
  const lower = pathStr.toLowerCase(pathStr);
  return lower.endsWith('.jpg') || lower.endsWith('.jpeg');
}

export {
  RemFSDelver,
};
