# SHA-Codename-One
SHA-256 Hashing for Codename One

Example of usage:

```
Form hi = new Form("SHA-256 hash", BoxLayout.y());
TextField bla = new TextField("", "Type Text Here", 20, TextArea.ANY);
TextArea encoded = new TextArea();
hi.addAll(bla, encoded);
        
bla.addDataChangedListener((a, b) -> {
   String s = bla.getText();
   String hash = SHA256Digest.sha256hash(s);
   encoded.setText(hash);
   hi.revalidate();
});

hi.show();
```
