package id3v2reader

import (
	"os"
	"testing"
)

func Test(t *testing.T) {
	filnames := []string{"testdata/test-v23.mp3", "testdata/test-v24.mp3"}

	for _, filname := range filnames {
		t.Logf("Opening file:%v\n", filname)
		if fil, filerr := os.Open(filname); filerr != nil {
			t.Errorf("Error: could not open file:%v\n", filname)
		} else {
			defer fil.Close()
			if id3tag, id3err := ReadID3(fil); id3err != nil {
				t.Errorf("Error in reading tag: %v\n", id3err)
			} else {
				title, titleerr := id3tag.GetTitle()
				if titleerr != nil {
					title = "Not Defined"
				}
				artist, artisterr := id3tag.GetArtist()
				if artisterr != nil {
					artist = "Not Defined"
				}
				album, albumerr := id3tag.GetAlbum()
				if albumerr != nil {
					album = "Not Defined"
				}
				composer, composererr := id3tag.GetComposer()
				if composererr != nil {
					composer = "Not Defined"
				}
				coverpic, coverpicerr := id3tag.GetCoverPic()
				if coverpicerr != nil {
					coverpic = []byte{0xff, 0xff, 0xff, 0xff}
				}
				t.Logf("--------------\n")
				t.Logf("Raw Data : %v\n", id3tag)
				t.Logf("--------------\n")
				t.Logf("File     : %v\n", filname)
				t.Logf("Title    : %v\n", title)
				t.Logf("Artist   : %v\n", artist)
				t.Logf("Album    : %v\n", album)
				t.Logf("Composer : %v\n", composer)
				t.Logf("CoverPic : %v\n", coverpic)
			}
		}
	}
}
