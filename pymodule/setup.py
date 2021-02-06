from distutils.core import setup, Extension

setup(name="tawny", version="1.0.1",
	ext_modules=[
		Extension(
			"tawny", ["pytawny.c"],
				extra_link_args = ["-lcrypto"]
		)
	]
)
