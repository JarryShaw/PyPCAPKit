class Pypcapkit < Formula
  include Language::Python::Virtualenv

  desc "Shiny new formula"
  homepage "https://github.com/JarryShaw/pypcapkit"
  url "https://files.pythonhosted.org/packages/ea/74/18cbaf2f5dff6a1ea9926a875c96c7c2077d1345dd4d53abd7f4f46ffe3f/pypcapkit-0.12.0.post1.tar.gz"
  sha256 "2c3cab54c6ad7872a73296bb042dd2b03621b1b1b530daa55e9c8bf7b1ba4063"

  depends_on "python3"

  resource "aenum" do
    url "https://files.pythonhosted.org/packages/7e/68/3ccd31abad04c4176df410b330b240e9e3c1531275b60836e9b863286364/aenum-2.1.2.tar.gz"
    sha256 "a3208e4b28db3a7b232ff69b934aef2ea1bf27286d9978e1e597d46f490e4687"
  end

  resource "chardet" do
    url "https://files.pythonhosted.org/packages/fc/bb/a5768c230f9ddb03acc9ef3f0d4a3cf93462473795d18e9535498c8f929d/chardet-3.0.4.tar.gz"
    sha256 "84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae"
  end

  resource "dictdumper" do
    url "https://files.pythonhosted.org/packages/a4/03/cb74ae23ce943670b772cd2a0985e39e0ca3b21c077781ed5fa77d076ba4/dictdumper-0.6.2.tar.gz"
    sha256 "cfaecd08913a5643493d1b20b063f472908741344ee9db6fa5aa10b1b456586e"
  end

  resource "dpkt" do
    url "https://files.pythonhosted.org/packages/bf/a4/8e4622fac4841b5e4a347fa9da4c057a7974258df247031280008d6ac0d0/dpkt-1.9.1.tar.gz"
    sha256 "c6a7ee878fa3d56e2c1fb44846f937046ba03b035da27382596e76f8d9f32967"
  end

  resource "emoji" do
    url "https://files.pythonhosted.org/packages/41/5a/5b2cbaf1f8936e54a3756c4f0587cbe0615cd50c6b31340214ea61f92782/emoji-0.5.1.tar.gz"
    sha256 "a9e9c08be9907c0042212c86dfbea0f61f78e9897d4df41a1d6307017763ad3e"
  end

  resource "pyshark" do
    url "https://files.pythonhosted.org/packages/4c/79/2b76e79080fa95d24bd3a49c1585e7b13f188b65fa05e47e67214bef9042/pyshark-0.4.1.tar.gz"
    sha256 "8965e8e2da50a7fe97f80b0b8db676a0bfc131aa8f4d6017e6b0cedc46b11288"
  end

  resource "scapy" do
    url "https://files.pythonhosted.org/packages/68/01/b9943984447e7ea6f8948e90c1729b78161c2bb3eef908430638ec3f7296/scapy-2.4.0.tar.gz"
    sha256 "452f714f5c2eac6fd0a6146b1dbddfc24dd5f4103f3ed76227995a488cfb2b73"
  end

  def install
    virtualenv_create(libexec, "python3")
    virtualenv_install_with_resources
  end

  test do
    false
  end
end
